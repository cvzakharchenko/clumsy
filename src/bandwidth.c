// bandwidth cap module
#include <stdlib.h>
#include <Windows.h>
#include <stdint.h>
#include <math.h>

#include "iup.h"
#include "common.h"

#define NAME "bandwidth"
#define BANDWIDTH_MIN  "0"
#define BANDWIDTH_MAX  "99999"
#define BANDWIDTH_DEFAULT 10
#define QUEUE_SIZE_MIN "0"
#define QUEUE_SIZE_MAX "1024"   // 1MB
#define QUEUE_SIZE_DEFAULT 0    // Default to old algorithm
#define MAX_QUEUES 1000
#define QUEUE_UNUSED_TIMEOUT 10000

//---------------------------------------------------------------------
// rate stats
//---------------------------------------------------------------------
typedef struct {
    int32_t initialized;
    uint32_t oldest_index;
    uint32_t oldest_ts;
    int64_t accumulated_count;
    int32_t sample_num;
    int window_size;
    float scale;
    uint32_t *array_sum;
    uint32_t *array_sample;
} CRateStats;


CRateStats* crate_stats_new(int window_size, float scale);

void crate_stats_delete(CRateStats *rate);

void crate_stats_reset(CRateStats *rate);

// call when packet arrives, count is the packet size in bytes
void crate_stats_update(CRateStats *rate, int32_t count, uint32_t now_ts);

// calculate rate
int32_t crate_stats_calculate(CRateStats *rate, uint32_t now_ts);


//---------------------------------------------------------------------
// configuration
//---------------------------------------------------------------------
static Ihandle *inboundCheckbox, *outboundCheckbox, *bandwidthInput, *queueSizeInput, *separateLimitCheckbox;

static volatile short bandwidthEnabled = 0,
    bandwidthInbound = 1, bandwidthOutbound = 1,
    separateLimit = 0;

static volatile LONG bandwidthLimit = BANDWIDTH_DEFAULT;
static volatile LONG maxQueueSize = QUEUE_SIZE_DEFAULT;  // in KB
static CRateStats *rateStats[2] = {NULL, NULL};

static Ihandle* bandwidthSetupUI() {
    Ihandle *bandwidthControlsBox = IupHbox(
        separateLimitCheckbox = IupToggle("Separate In/Out Limit", NULL),
        IupLabel("Queue(KB):"),
        queueSizeInput = IupText(NULL),
        inboundCheckbox = IupToggle("Inbound", NULL),
        outboundCheckbox = IupToggle("Outbound", NULL),
        IupLabel("Limit(KB/s):"),
        bandwidthInput = IupText(NULL),
        NULL
    );

    // Set up separate limit checkbox
    IupSetCallback(separateLimitCheckbox, "ACTION", (Icallback)uiSyncToggle);
    IupSetAttribute(separateLimitCheckbox, SYNCED_VALUE, (char*)&separateLimit);
    IupSetAttribute(separateLimitCheckbox, "VALUE", "OFF");

    // Queue size input setup
    IupSetAttribute(queueSizeInput, "VISIBLECOLUMNS", "4");
    IupSetAttribute(queueSizeInput, "VALUE", STR(QUEUE_SIZE_DEFAULT));
    IupSetCallback(queueSizeInput, "VALUECHANGED_CB", uiSyncInt32);
    IupSetAttribute(queueSizeInput, SYNCED_VALUE, (char*)&maxQueueSize);
    IupSetAttribute(queueSizeInput, INTEGER_MAX, QUEUE_SIZE_MAX);
    IupSetAttribute(queueSizeInput, INTEGER_MIN, QUEUE_SIZE_MIN);

    // Bandwidth input setup
    IupSetAttribute(bandwidthInput, "VISIBLECOLUMNS", "4");
    IupSetAttribute(bandwidthInput, "VALUE", STR(BANDWIDTH_DEFAULT));
    IupSetCallback(bandwidthInput, "VALUECHANGED_CB", uiSyncInt32);
    IupSetAttribute(bandwidthInput, SYNCED_VALUE, (char*)&bandwidthLimit);
    IupSetAttribute(bandwidthInput, INTEGER_MAX, BANDWIDTH_MAX);
    IupSetAttribute(bandwidthInput, INTEGER_MIN, BANDWIDTH_MIN);

    // Direction checkboxes setup
    IupSetCallback(inboundCheckbox, "ACTION", (Icallback)uiSyncToggle);
    IupSetAttribute(inboundCheckbox, SYNCED_VALUE, (char*)&bandwidthInbound);
    IupSetCallback(outboundCheckbox, "ACTION", (Icallback)uiSyncToggle);
    IupSetAttribute(outboundCheckbox, SYNCED_VALUE, (char*)&bandwidthOutbound);

    // enable by default to avoid confusing
    IupSetAttribute(inboundCheckbox, "VALUE", "ON");
    IupSetAttribute(outboundCheckbox, "VALUE", "ON");

    if (parameterized) {
        setFromParameter(inboundCheckbox, "VALUE", NAME"-inbound");
        setFromParameter(outboundCheckbox, "VALUE", NAME"-outbound");
        setFromParameter(bandwidthInput, "VALUE", NAME"-bandwidth");
        setFromParameter(queueSizeInput, "VALUE", NAME"-queuesize");
        setFromParameter(separateLimitCheckbox, "VALUE", NAME"-separate");
    }

    return bandwidthControlsBox;
}

//---------------------------------------------------------------------
// queue implementation
//---------------------------------------------------------------------
typedef struct {
    double tokensAvailable;
    uint32_t lastRefill;
} TokenBucket;

typedef struct {
    PacketNode headNode;
    PacketNode tailNode;
    PacketNode *head;
    PacketNode *tail;
    LONG dataSize;    // total bytes of packets in queue
    TransportAddr transportAddr;
    uint32_t lastUsed;
    TokenBucket bucket;
} PacketQueue;

static PacketQueue queues[MAX_QUEUES] = {0};
static int firstInactiveQueue = 0;

static INLINE_FUNCTION short isQueueEmpty(PacketQueue *q) {
    return q->head->next == q->tail;
}

static void initQueue(PacketQueue *q) {
    q->head = &q->headNode;
    q->tail = &q->tailNode;

    if (q->head->next == NULL && q->tail->next == NULL) {
        q->head->next = q->tail;
        q->tail->prev = q->head;
    } else {
        assert(isQueueEmpty(q));
    }
}

static void clearQueue(PacketQueue *q) {
    LOG("Clearing bandwidth queue, dropping %d bytes", q->dataSize);
    while (!isQueueEmpty(q)) {
        PacketNode *node = q->tail->prev;
        freeNode(popNode(node));
    }
    q->dataSize = 0;
}

static BOOL enqueuePacket(PacketQueue *q, PacketNode *packet) {
    int size = packet->packetLen;
    if (q->dataSize + size > maxQueueSize * 1024) {
        return FALSE;
    }

    insertAfter(packet, q->head);
    q->dataSize += size;
    return TRUE;
}

static PacketNode* dequeuePacket(PacketQueue *q) {
    if (isQueueEmpty(q)) {
        return NULL;
    }

    PacketNode *packet = popNode(q->tail->prev);
    q->dataSize -= packet->packetLen;
    return packet;
}

// We always need it because of potential timer wrap around. Without it, bucket doesn't need to be reset
void resetTokenBucket(TokenBucket* bucket, uint32_t nowTs, uint32_t tokenBucketMaxSize) {
    bucket->tokensAvailable = (double)tokenBucketMaxSize;
    bucket->lastRefill = nowTs;
}

BOOL trySpendTokens(TokenBucket* bucket, uint32_t nowTs, uint32_t bandwidthBps, uint32_t tokenBucketMaxSize, uint32_t tokensToSpend) {
    assert(bucket != NULL);

    uint32_t deltaTs = nowTs - bucket->lastRefill; // Timestamp wrap-around is handled by unsigned arithmetic
    double tokensToAdd = (double)deltaTs * (double)bandwidthBps / 1000.0;
    bucket->tokensAvailable = fmin((double)tokenBucketMaxSize, bucket->tokensAvailable + tokensToAdd);
    bucket->lastRefill = nowTs;

    if (bucket->tokensAvailable >= (double)tokensToSpend) {
        bucket->tokensAvailable -= (double)tokensToSpend;
        return 1; // Successfully spent tokens
    } else {
        return 0; // Not enough tokens
    }
}

static BOOL queueExpired(PacketQueue *q, uint32_t nowTs) {
    return nowTs - q->lastUsed > QUEUE_UNUSED_TIMEOUT;
}

static PacketQueue* findOrCreateQueue(TransportAddr *addr, uint32_t nowTs, uint32_t tokenBucketMaxSize) {
    for (int i = 0; i < firstInactiveQueue; i++) {
        if (memcmp(addr, &queues[i].transportAddr, sizeof(TransportAddr)) == 0) {
            if (queueExpired(&queues[i], nowTs)) {
                resetTokenBucket(&queues[i].bucket, nowTs, tokenBucketMaxSize);
            }
            queues[i].lastUsed = nowTs;
            return &queues[i];
        }
    }

    PacketQueue *queue = NULL;

    for (int i = 0; i < firstInactiveQueue; i++) {
        if (isQueueEmpty(&queues[i]) && queueExpired(&queues[i], nowTs)) {
            queue = &queues[i];
            break;
        }
    }

    if (queue == NULL) {
        if (firstInactiveQueue < MAX_QUEUES) {
            queue = &queues[firstInactiveQueue++];
        }
        else {
            LOG("Bandwidth queue overflow");
            return NULL;
        }
    }

    queue->lastUsed = nowTs;
    memcpy(&queue->transportAddr, addr, sizeof(TransportAddr));
    resetTokenBucket(&queue->bucket, nowTs, tokenBucketMaxSize);
    assert(queue->dataSize == 0);

    return queue;
}

//---------------------------------------------------------------------
// start up and close down
//---------------------------------------------------------------------

static void bandwidthStartUp() {
    startTimePeriod();
    for (int i = 0; i < MAX_QUEUES; i++) {
        initQueue(&queues[i]);
    }
    for (int i = 0; i < 2; i++) {
        if (rateStats[i]) crate_stats_delete(rateStats[i]);
        rateStats[i] = crate_stats_new(1000, 1000);
    }
    LOG("bandwidth enabled");
}

static void bandwidthCloseDown(PacketNode *head, PacketNode *tail) {
    UNREFERENCED_PARAMETER(tail);
    // Release remaining packets before closing
    for (int i = 0; i < MAX_QUEUES; i++) {
        while (!isQueueEmpty(&queues[i])) {
            PacketNode *packet = dequeuePacket(&queues[i]);
            insertAfter(packet, head);
        }
    }
    for (int i = 0; i < 2; i++) {
        if (rateStats[i]) crate_stats_delete(rateStats[i]);
        rateStats[i] = NULL;
    }
    endTimePeriod();
    LOG("bandwidth disabled");
}


//---------------------------------------------------------------------
// process
//---------------------------------------------------------------------
static short bandwidthProcess(PacketNode *head, PacketNode* tail) {
    int dropped = 0;
    DWORD now_ts = timeGetTime();
    int limit = bandwidthLimit * 1024;

    // allow 0 limit which should drop all
    if (limit < 0 || !rateStats[0] || !rateStats[1]) {
        return 0;
    }

    // Ignore queue-based algorithm when queue size == 0
    if (maxQueueSize == 0) {
        while (head->next != tail) {
            PacketNode *pac = head->next;
            int discard = 0;

            if (checkDirection(pac->addr.Outbound, bandwidthInbound, bandwidthOutbound)) {
                CRateStats *stats = rateStats[separateLimit && pac->addr.Outbound];
                int rate = crate_stats_calculate(stats, now_ts);
                int size = pac->packetLen;

                if (rate + size > limit) {
                    LOG("dropped with bandwidth %dKB/s, direction %s",
                        (int)bandwidthLimit, pac->addr.Outbound ? "OUTBOUND" : "INBOUND");
                    discard = 1;
                }
                else {
                    crate_stats_update(stats, size, now_ts);
                }
            }

            if (discard) {
                freeNode(popNode(pac));
                ++dropped;
            } else {
                head = head->next;
            }
        }

        return dropped > 0;
    }

    // Queue-based algorithm when queue size > 0

    // Enqueue all packets, or drop if queue is full
    while (tail->prev != head) {
        PacketNode *pac = tail->prev;
        if (!checkDirection(pac->addr.Outbound, bandwidthInbound, bandwidthOutbound)) {
            tail = tail->prev;
            continue;
        }

        popNode(pac);

        PacketQueue *targetQueue = findOrCreateQueue(&pac->transportAddr, now_ts, limit);
        if (!targetQueue || !enqueuePacket(targetQueue, pac)) {
            LOG("Dropped packet: queue full");
            freeNode(pac);
            dropped++;
        }
    }

    int queuesNotEmpty = 0;
    // Process as many packets as possible within the limit
    for (int i = 0; i < firstInactiveQueue; i++) {
        PacketQueue *targetQueue = &queues[i];
        while (!isQueueEmpty(targetQueue)) {
            PacketNode *queuedPacket = targetQueue->tail->prev;
            int size = queuedPacket->packetLen;
            if (!trySpendTokens(&targetQueue->bucket, now_ts, limit, limit, size)) {
                queuesNotEmpty++;
                break;
            }

            PacketNode *releasedPacket = dequeuePacket(targetQueue);
            insertAfter(releasedPacket, head);
        }
    }

    return dropped > 0 || queuesNotEmpty > 0;
}


//---------------------------------------------------------------------
// module
//---------------------------------------------------------------------
Module bandwidthModule = {
    "Bandwidth",
    NAME,
    (short*)&bandwidthEnabled,
    bandwidthSetupUI,
    bandwidthStartUp,
    bandwidthCloseDown,
    bandwidthProcess,
    // runtime fields
    0, 0, NULL
};



//---------------------------------------------------------------------
// create new CRateStat
//---------------------------------------------------------------------
CRateStats* crate_stats_new(int window_size, float scale)
{
    CRateStats *rate = (CRateStats*)malloc(sizeof(CRateStats));
    assert(rate);
    rate->array_sum = (uint32_t*)malloc(sizeof(uint32_t) * window_size);
    assert(rate->array_sum);
    rate->array_sample = (uint32_t*)malloc(sizeof(uint32_t) * window_size);
    assert(rate->array_sample);
    rate->window_size = window_size;
    rate->scale = scale;
    crate_stats_reset(rate);
    return rate;
}


//---------------------------------------------------------------------
// delete rate
//---------------------------------------------------------------------
void crate_stats_delete(CRateStats *rate)
{
    if (rate) {
        rate->window_size = 0;
        if (rate->array_sum) free(rate->array_sum);
        if (rate->array_sample) free(rate->array_sample);
        rate->array_sum = NULL;
        rate->array_sample = NULL;
        rate->initialized = 0;
        free(rate);
    }
}


//---------------------------------------------------------------------
// reset rate
//---------------------------------------------------------------------
void crate_stats_reset(CRateStats *rate)
{
    int i;
    for (i = 0; i < rate->window_size; i++) {
        rate->array_sum[i] = 0;
        rate->array_sample[i] = 0;
    }
    rate->initialized = 0;
    rate->sample_num = 0;
    rate->accumulated_count = 0;
    rate->oldest_ts = 0;
    rate->oldest_index = 0;
}


//---------------------------------------------------------------------
// evict oldest history
//---------------------------------------------------------------------
void crate_stats_evict(CRateStats *rate, uint32_t now_ts)
{
    if (rate->initialized == 0)
        return;

    uint32_t new_oldest_ts = now_ts - ((uint32_t)rate->window_size) + 1;

    if (((int32_t)(new_oldest_ts - rate->oldest_ts)) < 0)
        return;

    while (((int32_t)(rate->oldest_ts - new_oldest_ts)) < 0) {
        uint32_t index = rate->oldest_index;
        if (rate->sample_num == 0) break;
        rate->sample_num -= rate->array_sample[index];
        rate->accumulated_count -= rate->array_sum[index];
        rate->array_sample[index] = 0;
        rate->array_sum[index] = 0;
        rate->oldest_index++;
        if (rate->oldest_index >= (uint32_t)rate->window_size) {
            rate->oldest_index = 0;
        }
        rate->oldest_ts++;
    }
    assert(rate->sample_num >= 0);
    assert(rate->accumulated_count >= 0);
    rate->oldest_ts = new_oldest_ts;
}


//---------------------------------------------------------------------
// update stats
//---------------------------------------------------------------------
void crate_stats_update(CRateStats *rate, int32_t count, uint32_t now_ts)
{
    if (rate->initialized == 0) {
        rate->oldest_ts = now_ts;
        rate->oldest_index = 0;
        rate->accumulated_count = 0;
        rate->sample_num = 0;
        rate->initialized = 1;
    }

    if (((int32_t)(now_ts - rate->oldest_ts)) < 0) {
        return;
    }

    crate_stats_evict(rate, now_ts);

    int32_t offset = (int32_t)(now_ts - rate->oldest_ts);
    int32_t index = (rate->oldest_index + offset) % rate->window_size;

    rate->sample_num++;
    rate->accumulated_count += count;
    rate->array_sum[index] += count;
    rate->array_sample[index] += 1;
}


//---------------------------------------------------------------------
// calculate
//---------------------------------------------------------------------
int32_t crate_stats_calculate(CRateStats *rate, uint32_t now_ts)
{
    int32_t active_size = (int32_t)(now_ts - rate->oldest_ts + 1);
    float r;

    crate_stats_evict(rate, now_ts);

    if (rate->initialized == 0 ||
        rate->sample_num <= 0 ||
        active_size <= 1 ||
        active_size < rate->window_size) {
        return -1;
    }

    r = ((((float)rate->accumulated_count) * rate->scale) /
                rate->window_size) + 0.5f;

    return (int32_t)r;
}
