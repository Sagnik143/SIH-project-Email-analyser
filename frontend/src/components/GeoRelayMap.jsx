import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import { MapPin, Navigation, AlertTriangle, FastForward, Clock } from 'lucide-react';

export default function GeoRelayMap({ relay, originGeo }) {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);

  const trajectory = relay?.trajectory || [];
  const anomalies = relay?.hopAnomalies || [];

  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Destroy existing map instance if already initialized
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    // Default center (Atlantic view)
    let center = [25, 0];
    let zoom = 2;

    if (trajectory.length > 0) {
      center = [trajectory[0].lat, trajectory[0].lon];
      zoom = trajectory.length === 1 ? 4 : 2;
    }

    const map = L.map(mapContainerRef.current, {
      center,
      zoom,
      minZoom: 1.5,
      maxZoom: 14,
      attributionControl: false,
      zoomControl: false
    });

    // Add Leaflet zoom control at top right
    L.control.zoom({ position: 'topright' }).addTo(map);

    // CartoDB Dark Matter tile layer for cyber theme
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      subdomains: 'abcd',
      maxZoom: 19
    }).addTo(map);

    const latLngs = [];

    // Custom Icon Creators
    const createOriginIcon = () => L.divIcon({
      className: 'custom-origin-icon',
      html: `
        <div style="position: relative; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center;">
          <div style="position: absolute; width: 28px; height: 28px; border-radius: 50%; background: rgba(255, 51, 102, 0.4); animation: ping-slow 2s cubic-bezier(0, 0, 0.2, 1) infinite;"></div>
          <div style="width: 16px; height: 16px; border-radius: 50%; background: #ff3366; border: 2.5px solid #ffffff; box-shadow: 0 0 12px #ff3366; z-index: 2;"></div>
        </div>
      `,
      iconSize: [30, 30],
      iconAnchor: [15, 15]
    });

    const createHopIcon = (num, isDestination) => L.divIcon({
      className: 'custom-hop-icon',
      html: `
        <div style="width: 22px; height: 22px; border-radius: 50%; background: ${isDestination ? '#a855f7' : '#00f0ff'}; border: 2px solid #ffffff; box-shadow: 0 0 10px ${isDestination ? '#a855f7' : '#00f0ff'}; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: bold; color: #070a12; font-family: monospace;">
          ${num}
        </div>
      `,
      iconSize: [22, 22],
      iconAnchor: [11, 11]
    });

    // Add Markers for each trajectory point
    trajectory.forEach((pt, index) => {
      const isOrigin = pt.isOrigin || index === 0;
      const isDestination = index === trajectory.length - 1 && trajectory.length > 1;
      const pointLatLng = [pt.lat, pt.lon];
      latLngs.push(pointLatLng);

      const icon = isOrigin ? createOriginIcon() : createHopIcon(pt.hopNumber, isDestination);

      const marker = L.marker(pointLatLng, { icon }).addTo(map);

      const popupHtml = `
        <div style="font-size: 12px; line-height: 1.4; min-width: 180px;">
          <div style="font-weight: bold; color: ${isOrigin ? '#ff3366' : '#00f0ff'}; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; font-family: monospace;">
            ${isOrigin ? '🚨 ORIGINATING HOST (HOP ' + pt.hopNumber + ')' : (isDestination ? '🏁 FINAL DESTINATION MX' : '🔄 RELAY HOP ' + pt.hopNumber)}
          </div>
          <div style="font-family: monospace; font-weight: 600; color: #f1f5f9;">${pt.ip}</div>
          <div style="color: #94a3b8; font-size: 11px; margin-top: 2px;">${pt.city}, ${pt.country}</div>
          <div style="color: #64748b; font-size: 10px; margin-top: 4px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 4px;">
            MTA: ${pt.hostname || 'Unknown MTA'}
            ${pt.delaySeconds !== null ? `<br>Hop Latency: +${pt.delaySeconds}s` : ''}
          </div>
        </div>
      `;

      marker.bindPopup(popupHtml);
    });

    // Draw connecting polyline between hops
    if (latLngs.length > 1) {
      const polyline = L.polyline(latLngs, {
        color: '#00f0ff',
        weight: 3,
        opacity: 0.85,
        dashArray: '6, 8',
        lineCap: 'round'
      }).addTo(map);

      // Fit map bounds to encompass all hops with comfortable padding
      map.fitBounds(polyline.getBounds(), { padding: [40, 40], maxZoom: 6 });
    } else if (latLngs.length === 1) {
      map.setView(latLngs[0], 4);
    }

    mapInstanceRef.current = map;

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [trajectory]);

  return (
    <div className="glass-panel p-4 flex flex-col space-y-3">
      {/* Map Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Navigation className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
              Global Transmission Path & Origin GeoLocation
            </h3>
            <p className="text-[11px] text-slate-400">
              Interactive trace reconstruction of SMTP transmission hops across geographic coordinates
            </p>
          </div>
        </div>

        {/* Legend */}
        <div className="hidden sm:flex items-center gap-3 text-[11px] font-mono">
          <span className="flex items-center gap-1.5 text-rose-400">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block shadow-sm shadow-rose-500"></span> Origin Node
          </span>
          <span className="flex items-center gap-1.5 text-cyan-400">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block"></span> Relay Hop
          </span>
          <span className="flex items-center gap-1.5 text-purple-400">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block"></span> Edge MX
          </span>
        </div>
      </div>

      {/* Anomalies Alert Banner (e.g. Impossible Travel) */}
      {anomalies.length > 0 && (
        <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2 font-mono">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 animate-pulse" />
          <div className="flex-1">
            <strong className="font-bold">Impossible Physical Travel Anomaly Detected:</strong>{' '}
            {anomalies[0].alert} ({anomalies[0].speedKmPerSec} km/s transit speed indicates proxy or forged hop).
          </div>
        </div>
      )}

      {/* Map Canvas Container */}
      <div className="relative w-full h-[320px] rounded-lg overflow-hidden border border-slate-800 bg-[#060911]">
        <div ref={mapContainerRef} className="w-full h-full" />

        {/* Origin Quick Overlay Pin */}
        <div className="absolute bottom-3 left-3 z-[400] px-3 py-1.5 rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800 text-[11px] text-slate-300 flex items-center gap-2 font-mono">
          <MapPin className="w-3.5 h-3.5 text-rose-400" />
          <span>Origin: <strong>{originGeo?.city || 'Unknown'}, {originGeo?.country || 'Unknown'}</strong></span>
          <span className="text-slate-500">|</span>
          <span className="text-cyan-400">{relay?.totalHops || 0} Total Hops</span>
          <span className="text-slate-500">|</span>
          <span className="text-amber-400 flex items-center gap-1">
            <Clock className="w-3 h-3" /> {relay?.totalTransitTimeSeconds || 0}s Total Transit
          </span>
        </div>
      </div>
    </div>
  );
}
