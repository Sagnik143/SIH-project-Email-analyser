/**
 * World Map Component (Leaflet)
 */

import { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

export default function WorldMap({ ipResults = [], height = '400px', showTrace = false }) {
  const mapRef = useRef(null);
  const mapInstance = useRef(null);

  useEffect(() => {
    if (!mapRef.current) return;

    // Initialize map
    if (!mapInstance.current) {
      mapInstance.current = L.map(mapRef.current, {
        center: [20, 0],
        zoom: 2,
        zoomControl: true,
        attributionControl: true,
      });

      // Dark mode tile layer
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors © <a href="https://carto.com/">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19,
      }).addTo(mapInstance.current);
    }

    const map = mapInstance.current;

    // Clear existing layers
    map.eachLayer((layer) => {
      if (layer instanceof L.Marker || layer instanceof L.Polyline || layer instanceof L.CircleMarker) {
        map.removeLayer(layer);
      }
    });

    // Add markers for each IP
    const validIPs = ipResults.filter(ip => ip.lat && ip.lon && !ip.error);

    if (validIPs.length === 0) return;

    const bounds = [];

    validIPs.forEach((ip, index) => {
      const latlng = [ip.lat, ip.lon];
      bounds.push(latlng);

      const isFirst = index === 0;
      const isLast = index === validIPs.length - 1;

      // Custom circle marker
      const color = isFirst ? '#dc2626' : isLast ? '#059669' : '#2563eb';
      const radius = isFirst || isLast ? 10 : 7;

      const marker = L.circleMarker(latlng, {
        radius,
        fillColor: color,
        fillOpacity: 0.8,
        color: color,
        weight: 2,
        opacity: 0.6,
      }).addTo(map);

      // Popup
      const popupContent = `
        <div style="min-width: 200px;">
          <div style="font-weight: 700; font-size: 0.9rem; margin-bottom: 6px; color: ${color};">
            ${isFirst ? '📤 Origin' : isLast ? '📥 Destination' : '🔄 Relay'} — ${ip.ip}
          </div>
          <div style="font-size: 0.8rem; line-height: 1.6;">
            <div>📍 ${ip.city}, ${ip.region}</div>
            <div>🌍 ${ip.country}</div>
            <div>🏢 ${ip.isp}</div>
            <div>🔗 ${ip.org}</div>
            ${ip.isProxy ? '<div style="color: #dc2626;">⚠️ Proxy/VPN Detected</div>' : ''}
            ${ip.isHosting ? '<div style="color: #d97706;">☁️ Hosting Provider</div>' : ''}
          </div>
        </div>
      `;

      marker.bindPopup(popupContent);

      // Pulsing ring for origin
      if (isFirst) {
        L.circleMarker(latlng, {
          radius: 20,
          fillColor: color,
          fillOpacity: 0.15,
          color: color,
          weight: 1,
          opacity: 0.3,
        }).addTo(map);
      }
    });

    // Draw trace line
    if (showTrace && validIPs.length > 1) {
      const coords = validIPs.map(ip => [ip.lat, ip.lon]);

      // Animated line
      L.polyline(coords, {
        color: '#2563eb',
        weight: 2,
        opacity: 0.6,
        dashArray: '10, 10',
        dashOffset: '0',
      }).addTo(map);

      // Glow line
      L.polyline(coords, {
        color: '#2563eb',
        weight: 6,
        opacity: 0.15,
      }).addTo(map);
    }

    // Fit bounds
    if (bounds.length > 1) {
      map.fitBounds(bounds, { padding: [50, 50] });
    } else if (bounds.length === 1) {
      map.setView(bounds[0], 6);
    }

    return () => {};
  }, [ipResults, showTrace]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (mapInstance.current) {
        mapInstance.current.remove();
        mapInstance.current = null;
      }
    };
  }, []);

  return (
    <div className="map-container" style={{ height }}>
      <div ref={mapRef} style={{ height: '100%', width: '100%' }} />
    </div>
  );
}
