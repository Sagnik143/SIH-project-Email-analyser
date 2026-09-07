import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import { AlertTriangle, Clock, MapPin, Compass, Info } from 'lucide-react';

export default function GeoRelayMap({ relay, originGeo }) {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);

  const trajectory = relay?.trajectory || [];
  const anomalies = relay?.hopAnomalies || [];

  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

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

    L.control.zoom({ position: 'topright' }).addTo(map);

    // OpenStreetMap Clean High-Resolution Tile Layer
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap'
    }).addTo(map);

    const latLngs = [];

    const createOriginIcon = () => L.divIcon({
      className: 'custom-origin-icon',
      html: `
        <div style="position: relative; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center;">
          <div style="position: absolute; width: 30px; height: 30px; border-radius: 50%; background: rgba(244, 63, 94, 0.35); animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;"></div>
          <div style="width: 18px; height: 18px; border-radius: 50%; background: #f43f5e; border: 3px solid #ffffff; box-shadow: 0 4px 12px rgba(244, 63, 94, 0.5); z-index: 2;"></div>
        </div>
      `,
      iconSize: [32, 32],
      iconAnchor: [16, 16]
    });

    const createHopIcon = (num, isDestination) => L.divIcon({
      className: 'custom-hop-icon',
      html: `
        <div style="width: 24px; height: 24px; border-radius: 50%; background: ${isDestination ? '#8b5cf6' : '#3b82f6'}; border: 2.5px solid #ffffff; box-shadow: 0 4px 10px rgba(59, 130, 246, 0.4); display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 800; color: #ffffff; font-family: sans-serif;">
          ${num}
        </div>
      `,
      iconSize: [24, 24],
      iconAnchor: [12, 12]
    });

    trajectory.forEach((pt, index) => {
      const isOrigin = pt.isOrigin || index === 0;
      const isDestination = index === trajectory.length - 1 && trajectory.length > 1;
      const pointLatLng = [pt.lat, pt.lon];
      latLngs.push(pointLatLng);

      const icon = isOrigin ? createOriginIcon() : createHopIcon(pt.hopNumber, isDestination);

      const marker = L.marker(pointLatLng, { icon }).addTo(map);

      const popupHtml = `
        <div style="font-size: 12px; line-height: 1.5; min-width: 190px; padding: 2px;">
          <div style="font-weight: 800; color: ${isOrigin ? '#e11d48' : '#2563eb'}; font-size: 11px; text-transform: uppercase; margin-bottom: 4px;">
            ${isOrigin ? 'Claimed Origin (Hop 1, UNVERIFIED)' : (isDestination ? 'Destination Inbox MX' : 'Relay Hop ' + pt.hopNumber)}
          </div>
          <div style="font-family: monospace; font-weight: 700; color: #0f172a; font-size: 13px;">${pt.ip}</div>
          <div style="color: #475569; font-size: 12px; margin-top: 2px;">📍 Observed Infrastructure: ${pt.city}, ${pt.country}</div>
          <div style="color: #64748b; font-size: 11px; margin-top: 4px; border-top: 1px solid #f1f5f9; padding-top: 4px;">
            MTA: <strong>${pt.hostname || 'Direct'}</strong>
            ${pt.delaySeconds !== null ? `<br>Transit Delay: +${pt.delaySeconds}s` : ''}
          </div>
        </div>
      `;

      marker.bindPopup(popupHtml);
    });

    if (latLngs.length > 1) {
      const polyline = L.polyline(latLngs, {
        color: '#3b82f6',
        weight: 3.5,
        opacity: 0.9,
        dashArray: '8, 8',
        lineCap: 'round'
      }).addTo(map);

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
    <div className="app-card p-6 space-y-3.5 bg-white border-slate-200 shadow-xs relative isolate z-0">
      
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-blue-50 text-blue-600 border border-blue-100">
            <Compass className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight">
              Observable Relay Path & Infrastructure Location
            </h3>
            <p className="text-xs text-slate-500">
              Reconstructed transmission path between observable mail relay infrastructure
            </p>
          </div>
        </div>

        {/* Legend */}
        <div className="hidden sm:flex items-center gap-3 text-xs font-semibold">
          <span className="flex items-center gap-1.5 text-rose-600">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block shadow-xs"></span> Claimed Origin (UNVERIFIED)
          </span>
          <span className="flex items-center gap-1.5 text-blue-600">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span> Relay Server
          </span>
          <span className="flex items-center gap-1.5 text-purple-600">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block"></span> Destination
          </span>
        </div>
      </div>

      {/* Geolocation Limitation Notice */}
      <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-slate-600 text-[11px] flex items-start gap-2">
        <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
        <span className="leading-relaxed">
          <strong>Forensic Notice:</strong> IP geolocation describes the registered/observed infrastructure associated with an IP address. It does not establish the physical location or identity of a person.
        </span>
      </div>

      {/* Geolocation Unavailable Banner if applicable */}
      {originGeo?.status === 'unavailable' && (
        <div className="p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-[11px] flex items-center gap-2">
          <span>⚠️</span>
          <span>
            <strong>Service Notice:</strong> Geolocation enrichment service is temporarily unavailable ({originGeo.reason || 'Offline'}). Transmission hop telemetry is displayed without coordinates.
          </span>
        </div>
      )}

      {/* Anomalies Alert - Timing & Routing Inconsistency */}
      {anomalies.length > 0 && (
        <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-xs flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600" />
          <div className="flex-1 leading-relaxed">
            <strong>Relay Timing / Routing Inconsistency:</strong> {anomalies[0].alert || 'Timestamp inconsistency detected between observed relay entries.'}
            <span className="block text-[10px] text-amber-700 italic mt-0.5">
              Differences may reflect unsynchronized server clocks, intermediate MTA queuing, or timezone configuration disparities.
            </span>
          </div>
        </div>
      )}

      {/* Map Container */}
      <div className="relative w-full h-[320px] rounded-xl overflow-hidden border border-slate-200 shadow-inner bg-slate-50 isolate z-0">
        <div ref={mapContainerRef} className="w-full h-full z-0" />

        {/* Origin Quick Overlay Pin */}
        <div className="absolute bottom-3 left-3 z-10 px-3.5 py-2 rounded-xl bg-white/95 backdrop-blur-md border border-slate-200 text-xs text-slate-700 shadow-md flex items-center gap-2.5 font-medium">
          <MapPin className="w-4 h-4 text-rose-600" />
          <span>Earliest Infrastructure Node: <strong className="text-slate-900">{originGeo?.city || 'Unknown'}, {originGeo?.country || 'Unknown'}</strong></span>
          <span className="text-slate-300">|</span>
          <span className="text-blue-600 font-semibold">{relay?.totalHops || 0} Hops Traversed</span>
          <span className="text-slate-300">|</span>
          <span className="text-slate-600 flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-slate-400" /> {relay?.totalTransitTimeSeconds || 0}s Total Latency
          </span>
        </div>
      </div>

    </div>
  );
}
