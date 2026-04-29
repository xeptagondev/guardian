<script setup lang="ts">
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

interface LatLng {
    lat: number;
    lng: number;
}

const props = defineProps<{
    /** Single point — used when no polygon or only one coord is provided. */
    lat?: number | null;
    lng?: number | null;
    /**
     * Project boundary or multi-point trace. 3+ points → polygon.
     * 1-2 points → falls back to markers.
     */
    polygon?: LatLng[] | null;
    name: string;
}>();

const mapContainer = ref<HTMLElement | null>(null);
let map: L.Map | null = null;

const dotIcon = () =>
    L.divIcon({
        className: '',
        html: '<div style="width:12px;height:12px;background:#1a9850;border:2px solid #fff;border-radius:50%;box-shadow:0 1px 4px rgba(0,0,0,0.3)"></div>',
        iconSize: [12, 12],
        iconAnchor: [6, 6],
    });

onMounted(() => {
    if (!mapContainer.value) return;

    const polygonPoints = (props.polygon ?? []).filter(
        (p) => Number.isFinite(p.lat) && Number.isFinite(p.lng),
    );
    const hasPoint = Number.isFinite(props.lat) && Number.isFinite(props.lng);

    if (polygonPoints.length === 0 && !hasPoint) return;

    const initialCenter: [number, number] = polygonPoints.length > 0
        ? [polygonPoints[0].lat, polygonPoints[0].lng]
        : [props.lat as number, props.lng as number];

    map = L.map(mapContainer.value, {
        center: initialCenter,
        zoom: 8,
        zoomControl: true,
        scrollWheelZoom: true,
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
        maxZoom: 18,
    }).addTo(map);

    if (polygonPoints.length >= 3) {
        // Boundary polygon — colour coded green for project areas.
        const layer = L.polygon(
            polygonPoints.map((p) => [p.lat, p.lng]),
            {
                color: '#1a9850',
                weight: 2,
                fillColor: '#1a9850',
                fillOpacity: 0.18,
            },
        )
            .bindPopup(
                `<strong style="font-size:12px">${escapeHtml(props.name)}</strong>` +
                `<div style="font-size:11px;color:#666;margin-top:2px">` +
                `${polygonPoints.length} boundary points` +
                `</div>`,
            )
            .addTo(map);
        map.fitBounds(layer.getBounds(), { padding: [24, 24] });

        // Drop a small marker at each vertex so individual points are visible
        // even when zoomed out and the polygon collapses to a sliver.
        for (const p of polygonPoints) {
            L.marker([p.lat, p.lng], { icon: dotIcon() }).addTo(map);
        }
    } else if (polygonPoints.length > 0) {
        // 1-2 points — render as markers without a polygon.
        for (const p of polygonPoints) {
            L.marker([p.lat, p.lng], { icon: dotIcon() })
                .bindPopup(`<strong style="font-size:12px">${escapeHtml(props.name)}</strong>`)
                .addTo(map);
        }
        if (polygonPoints.length === 1) {
            map.setView([polygonPoints[0].lat, polygonPoints[0].lng], 8);
        } else {
            map.fitBounds(L.latLngBounds(polygonPoints.map((p) => [p.lat, p.lng])), {
                padding: [40, 40],
            });
        }
    } else {
        // Pure single-point fallback (legacy callers).
        L.marker([props.lat as number, props.lng as number], { icon: dotIcon() })
            .bindPopup(`<strong style="font-size:12px">${escapeHtml(props.name)}</strong>`)
            .addTo(map);
    }
});

onUnmounted(() => {
    map?.remove();
    map = null;
});

function escapeHtml(s: string): string {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
</script>

<template>
    <div ref="mapContainer" class="h-full w-full rounded-lg" />
</template>
