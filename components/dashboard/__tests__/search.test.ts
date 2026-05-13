
/* eslint-disable */
import { LiveNetworkEvent } from '@/hooks/use-socket';

/**
 * Mock filter function that mimics the logic in live-network-console.tsx
 */
export function filterNetworks(networks: LiveNetworkEvent[], query: string) {
  if (!query.trim()) return networks;
  
  const lowerQuery = query.toLowerCase().trim();
  const normalizedQuery = lowerQuery.replace(/[:-]/g, '').toUpperCase();

  return networks.filter((network) => {
    const ssidMatch = (network.ssid || 'Hidden').toLowerCase().includes(lowerQuery);
    const normalizedBssid = network.bssid.replace(/[:-]/g, '').toUpperCase();
    const bssidMatch = normalizedBssid.includes(normalizedQuery);

    return ssidMatch || bssidMatch;
  });
}

// Unit Tests
describe('Search Functionality', () => {
  const mockNetworks: LiveNetworkEvent[] = [
    {
      bssid: 'AA:BB:CC:DD:EE:FF',
      ssid: 'Home_WiFi',
      signal: -45,
      classification: 'LEGIT',
      last_seen: new Date().toISOString(),
      channel: 6,
      sensor_id: 1,
      manufacturer: 'Apple'
    },
    {
      bssid: '11:22:33:44:55:66',
      ssid: 'Office_Guest',
      signal: -60,
      classification: 'SUSPICIOUS',
      last_seen: new Date().toISOString(),
      channel: 11,
      sensor_id: 1,
      manufacturer: 'Intel'
    },
    {
      bssid: 'DE:AD:BE:EF:00:11',
      ssid: '', // Hidden SSID
      signal: -80,
      classification: 'ROGUE',
      last_seen: new Date().toISOString(),
      channel: 1,
      sensor_id: 2,
      manufacturer: 'Unknown'
    }
  ];

  test('should filter by SSID (case-insensitive)', () => {
    const results = filterNetworks(mockNetworks, 'home');
    expect(results).toHaveLength(1);
    expect(results[0].ssid).toBe('Home_WiFi');
  });

  test('should filter by BSSID with colons', () => {
    const results = filterNetworks(mockNetworks, 'AA:BB:CC');
    expect(results).toHaveLength(1);
    expect(results[0].bssid).toBe('AA:BB:CC:DD:EE:FF');
  });

  test('should filter by BSSID without colons', () => {
    const results = filterNetworks(mockNetworks, 'AABBCC');
    expect(results).toHaveLength(1);
    expect(results[0].bssid).toBe('AA:BB:CC:DD:EE:FF');
  });

  test('should filter by BSSID with hyphens', () => {
    const results = filterNetworks(mockNetworks, '11-22-33');
    expect(results).toHaveLength(1);
    expect(results[0].bssid).toBe('11:22:33:44:55:66');
  });

  test('should handle partial SSID matches', () => {
    const results = filterNetworks(mockNetworks, 'ice');
    expect(results).toHaveLength(1);
    expect(results[0].ssid).toBe('Office_Guest');
  });

  test('should find "Hidden" networks when searching for "hidden"', () => {
    const results = filterNetworks(mockNetworks, 'hidden');
    expect(results).toHaveLength(1);
    expect(results[0].ssid).toBe('');
  });

  test('should return all networks on empty query', () => {
    const results = filterNetworks(mockNetworks, '');
    expect(results).toHaveLength(mockNetworks.length);
  });

  test('should return empty list when no matches found', () => {
    const results = filterNetworks(mockNetworks, 'NonExistentNetwork');
    expect(results).toHaveLength(0);
  });
});
