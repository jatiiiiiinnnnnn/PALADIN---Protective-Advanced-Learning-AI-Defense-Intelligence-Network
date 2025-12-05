// Centralized Elasticsearch calls.
// Edit BASE_URL to point to your ES endpoint if different.
import axios from "axios";

const BASE_URL = 

/**
 * Generic POST helper for ES
 * returns data or throws error
 */
async function esPost(body) {
  const res = await axios.post(BASE_URL, body);
  return res.data;
}

/**
 * Get most recent logs (for table)
 * returns array of _source objects
 */
export async function getRecentLogs() {
  const body = {
    size: 50,
    sort: [{ "@timestamp": "desc" }],
    query: { match_all: {} }
  };

  const data = await esPost(body);
  // defensive: if hits absent, return empty array
  return (data?.hits?.hits || []).map(h => h._source);
}

/**
 * Get attack distribution aggregated by ai_attack_type
 * returns buckets: [{ key: "DOS", doc_count: 12 }, ...]
 */
export async function getAttackDistribution() {
  const body = {
    size: 0,
    aggs: {
      attack_types: { terms: { field: "ai_attack_type.keyword", size: 20 } }
    }
  };

  const data = await esPost(body);
  return data?.aggregations?.attack_types?.buckets || [];
}

/**
 * Get attack timeline histogram, each bucket contains sub-aggregation by type
 * returns buckets array in ES format
 */
export async function getAttackTimeline() {
  const body = {
    size: 0,
    aggs: {
      attacks_over_time: {
        date_histogram: {
          field: "@timestamp",
          calendar_interval: "minute"
        },
        aggs: {
          by_type: { terms: { field: "ai_attack_type.keyword", size: 20 } }
        }
      }
    }
  };

  const data = await esPost(body);
  return data?.aggregations?.attacks_over_time?.buckets || [];
}
