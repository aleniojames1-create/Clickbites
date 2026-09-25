import crypto from 'node:crypto';

function haversineKm(aLat, aLon, bLat, bLon) {
  const R = 6371;
  const toRad = n => n * Math.PI / 180;
  const dLat = toRad(bLat - aLat);
  const dLon = toRad(bLon - aLon);
  const x = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(aLat)) * Math.cos(toRad(bLat)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1 - x));
}

export function hashDeviceId(deviceId) {
  return crypto.createHash('sha256').update(String(deviceId || 'unknown')).digest('hex');
}

export function assessLoginRisk(db, { userId, ip, userAgent, deviceId, latitude, longitude }) {
  let score = 0;
  const signals = [];
  const deviceHash = hashDeviceId(deviceId);
  const recentFailures = db.prepare(`SELECT COUNT(*) count FROM login_events WHERE user_id=? AND success=0 AND created_at >= datetime('now','-15 minutes')`).get(userId)?.count || 0;
  if (recentFailures >= 3) { score += Math.min(35, recentFailures * 8); signals.push('repeated_failed_logins'); }

  const recentIp = db.prepare(`SELECT 1 FROM login_events WHERE user_id=? AND success=1 AND ip_address=? ORDER BY created_at DESC LIMIT 1`).get(userId, ip || '')
  const knownIp = db.prepare(`SELECT 1 FROM login_events WHERE user_id=? AND success=1 AND ip_address IS NOT NULL ORDER BY created_at DESC LIMIT 1`).get(userId);
  if (knownIp && !recentIp) { score += 20; signals.push('new_ip'); }

  const knownDevice = db.prepare(`SELECT 1 FROM login_events WHERE user_id=? AND success=1 AND device_hash=? LIMIT 1`).get(userId, deviceHash);
  if (!knownDevice) { score += 20; signals.push('new_device'); }

  const lastLocation = db.prepare(`SELECT latitude,longitude FROM user_locations WHERE user_id=? AND latitude IS NOT NULL AND longitude IS NOT NULL ORDER BY created_at DESC LIMIT 1`).get(userId);
  let distanceKm = null;
  if (latitude != null && longitude != null && lastLocation) {
    distanceKm = haversineKm(Number(latitude), Number(longitude), Number(lastLocation.latitude), Number(lastLocation.longitude));
    if (distanceKm > 500) { score += 30; signals.push('large_location_change'); }
    else if (distanceKm > 100) { score += 15; signals.push('unusual_location'); }
  } else if (latitude == null || longitude == null) {
    score += 5;
    signals.push('location_unavailable');
  }

  const recentVelocity = db.prepare(`SELECT COUNT(*) count FROM login_events WHERE user_id=? AND created_at >= datetime('now','-5 minutes')`).get(userId)?.count || 0;
  if (recentVelocity >= 5) { score += 25; signals.push('high_login_velocity'); }

  const riskLevel = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
  return { score: Math.min(score, 100), riskLevel, signals, distanceKm, deviceHash, userAgent: String(userAgent || '').slice(0, 500) };
}
