#!/bin/sh
# Scanner container entrypoint.
#
# 1. Make sure the free DB-IP Lite geolocation databases (country + ASN) are in
#    $GEO_DATA_DIR. They are downloaded when missing or older than 35 days.
#    A failed download never stops the scanner: geolocation is optional.
# 2. exec nightwatch.
#
# DB-IP Lite data is licensed under CC BY 4.0: "IP Geolocation by DB-IP"
# (https://db-ip.com). Set GEO_DOWNLOAD=false to skip the download, for
# example on hosts without internet access or to supply your own files.
set -u

GEO_DATA_DIR="${GEO_DATA_DIR:-/data/geo}"
GEO_DOWNLOAD="${GEO_DOWNLOAD:-true}"
GEO_MAX_AGE_DAYS="${GEO_MAX_AGE_DAYS:-35}"

log() {
	echo "entrypoint: $*" >&2
}

# fetch_dbip <edition> <destination>
#   edition: country-lite | asn-lite
# DB-IP publishes a new file every month. The current month can be missing
# for the first days, so the previous month is tried as well.
fetch_dbip() {
	edition="$1"
	dest="$2"

	if [ -s "$dest" ] && [ -z "$(find "$dest" -mtime "+$GEO_MAX_AGE_DAYS" 2>/dev/null)" ]; then
		return 0
	fi

	this_month="$(date -u +%Y-%m)"
	last_month="$(date -u -d "@$(($(date -u +%s) - 32 * 86400))" +%Y-%m 2>/dev/null || true)"

	for month in $this_month $last_month; do
		url="https://download.db-ip.com/free/dbip-${edition}-${month}.mmdb.gz"
		tmp="${dest}.download"
		if curl -fsSL --retry 2 --connect-timeout 15 --max-time 300 "$url" -o "${tmp}.gz" &&
			gunzip -c "${tmp}.gz" >"$tmp" && [ -s "$tmp" ]; then
			mv -f "$tmp" "$dest"
			rm -f "${tmp}.gz"
			log "downloaded DB-IP ${edition} ${month} to ${dest}"
			return 0
		fi
		rm -f "$tmp" "${tmp}.gz"
	done

	if [ -s "$dest" ]; then
		log "could not refresh DB-IP ${edition}; keeping the existing file"
	else
		log "could not download DB-IP ${edition}; geolocation is disabled until the next start"
	fi
	return 0
}

if [ "$GEO_DOWNLOAD" = "true" ]; then
	if mkdir -p "$GEO_DATA_DIR" 2>/dev/null && [ -w "$GEO_DATA_DIR" ]; then
		fetch_dbip country-lite "${IP_ENRICHMENT_DB_PATH:-$GEO_DATA_DIR/dbip-country-lite.mmdb}"
		fetch_dbip asn-lite "${IP_ASN_DB_PATH:-$GEO_DATA_DIR/dbip-asn-lite.mmdb}"
	else
		log "$GEO_DATA_DIR is not writable; skipping the geolocation download"
	fi
fi

exec nightwatch "$@"
