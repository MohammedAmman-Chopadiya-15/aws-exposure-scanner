import { useState, useEffect, useCallback } from 'react';

export function useCloudAudit(pollIntervalMs = 120000) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const apiEndpoint = import.meta.env.VITE_API_URL;
      const apiKey = import.meta.env.VITE_API_KEY;

      const res = await fetch(apiEndpoint, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'x-api-token': apiKey
        }
      });

      if (!res.ok) {
        throw new Error(`HTTP error! Status: ${res.status}`);
      }

      const json = await res.json();
      const findings = Array.isArray(json) ? json : (json.findings || []);
      setData(findings);
    } catch (err) {
      console.error("Error fetching scan data from AWS API Gateway:", err);
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => {
      fetchData();
    }, pollIntervalMs);

    return () => clearInterval(interval);
  }, [fetchData, pollIntervalMs]);

  return { data, loading, error, refetch: fetchData };
}