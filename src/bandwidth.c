// bandwidth cap module
#include <stdlib.h>
#include <Windows.h>
#include <stdint.h>

#include "iup.h"
#include "common.h"

#define NAME "bandwidth"
#define BANDWIDTH_MIN  "0"
#define BANDWIDTH_MAX  "99999"
#define BANDWIDTH_DEFAULT 10
#define QUEUE_SIZE_MIN "0"
#define QUEUE_SIZE_MAX "1024"   // 1MB
#define QUEUE_SIZE_DEFAULT 0    // Default to old algorithm

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
static Ihandle *inboundCheckbox, *outboundCheckbox, *bandwidthInput, *queueSizeInput;

static volatile short bandwidthEnabled = 0,
    bandwidthInbound = 1, bandwidthOutbound = 1;

static volatile LONG bandwidthLimit = BANDWIDTH_DEFAULT;
static volatile LONG maxQueueSize = QUEUE_SIZE_DEFAULT;  // in KB
static CRateStats *inboundStats = NULL, *outboundStats = NULL;


static Ihandle* bandwidthSetupUI() {
    Ihandle *bandwidthControlsBox = IupHbox(
        IupLabel("Queue(KB):"),
        queueSizeInput = IupText(NULL),
        inboundCheckbox = IupToggle("Inbound", NULL),
        outboundCheckbox = IupToggle("Outbound", NULL),
        IupLabel("Limit(KB/s):"),
        bandwidthInput = IupText(NULL),
        NULL
    );

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
    }

    return bandwidthControlsBox;
}

//---------------------------------------------------------------------
// queue implementation
//---------------------------------------------------------------------
static PacketNode queueHeadNode = {0}, queueTailNode = {0};
static PacketNode *queueHead = &queueHeadNode, *queueTail = &queueTailNode;
static LONG queueSize = 0;        // number of packets in queue
static LONG queueDataSize = 0;    // total bytes in queue

static INLINE_FUNCTION short isQueueEmpty() {
    short ret = queueHead->next == queueTail;
    if (ret) assert(queueSize == 0);
    return ret;
}

static void initQueue() {
    if (queueHead->next == NULL && queueTail->next == NULL) {
        queueHead->next = queueTail;
        queueTail->prev = queueHead;
        queueSize = 0;
        queueDataSize = 0;
    } else {
        assert(isQueueEmpty());
    }
}

static void clearQueue() {
    LOG("Clearing bandwidth queue, dropping %d packets (%d bytes)", queueSize, queueDataSize);
    while (!isQueueEmpty()) {
        PacketNode *node = queueTail->prev;
        freeNode(popNode(node));
        queueSize--;
    }
    queueDataSize = 0;
}

static BOOL enqueuePacket(PacketNode *packet) {
    int size = packet->packetLen;
    if (queueDataSize + size > maxQueueSize * 1024) {
        LOG("Queue full (%d bytes), dropping packet", queueDataSize);
        return FALSE;
    }

    insertAfter(packet, queueHead);
    queueSize++;
    queueDataSize += size;
    return TRUE;
}

static PacketNode* dequeuePacket() {
    if (isQueueEmpty()) {
        return NULL;
    }

    PacketNode *packet = popNode(queueTail->prev);
    queueSize--;
    queueDataSize -= packet->packetLen;
    return packet;
}

//---------------------------------------------------------------------
// start up and close down
//---------------------------------------------------------------------

static void bandwidthStartUp() {
    initQueue();
    startTimePeriod();
    if (inboundStats) crate_stats_delete(inboundStats);
    if (outboundStats) crate_stats_delete(outboundStats);
    inboundStats = crate_stats_new(1000, 1000);
    outboundStats = crate_stats_new(1000, 1000);
    LOG("bandwidth enabled");
}

static void bandwidthCloseDown(PacketNode *head, PacketNode *tail) {
    UNREFERENCED_PARAMETER(tail);
    // Release remaining packets before closing
    while (!isQueueEmpty()) {
        PacketNode *packet = dequeuePacket();
        insertAfter(packet, head);
    }
    endTimePeriod();
    if (inboundStats) crate_stats_delete(inboundStats);
    if (outboundStats) crate_stats_delete(outboundStats);
    inboundStats = outboundStats = NULL;
    LOG("bandwidth disabled");
}


//---------------------------------------------------------------------
// process
//---------------------------------------------------------------------
static short bandwidthProcess(PacketNode *head, PacketNode* tail) {
    int dropped = 0;
    DWORD now_ts = timeGetTime();
    int limit = bandwidthLimit * 1024;

    //    allow 0 limit which should drop all
    if (limit < 0 || !inboundStats || !outboundStats) {
        return 0;
    }

    // Ignore queue-based algorithm when queue size == 0
    if (maxQueueSize == 0) {
        while (head->next != tail) {
            PacketNode *pac = head->next;
            int discard = 0;

            if (checkDirection(pac->addr.Outbound, bandwidthInbound, bandwidthOutbound)) {
                CRateStats *stats = pac->addr.Outbound ? outboundStats : inboundStats;
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
    while (tail->prev != head) {
        PacketNode *pac = tail->prev;
        if (!checkDirection(pac->addr.Outbound, bandwidthInbound, bandwidthOutbound)) {
            tail = tail->prev;
            continue;
        }
        PacketNode *node = popNode(pac);
        if (!enqueuePacket(node)) {
            LOG("Dropped packet: queue full (%d bytes)", queueDataSize);
            freeNode(node);
            dropped++;
        }
    }

    while (!isQueueEmpty()) {
        PacketNode *queuedPacket = queueTail->prev;
        CRateStats *stats = queuedPacket->addr.Outbound ? outboundStats : inboundStats;
        int rate = crate_stats_calculate(stats, now_ts);
        int size = queuedPacket->packetLen;

        if (rate + size > limit) {
            break;
        }

        PacketNode *releasedPacket = dequeuePacket();
        insertAfter(releasedPacket, head);
        crate_stats_update(stats, size, now_ts);
    }

    return dropped > 0 || !isQueueEmpty();
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
