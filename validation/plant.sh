#!/usr/bin/env bash
# Load FAKE personal data into the canary tables (Terraform created the empty tables, datasets and bucket).
#   ./validation/plant.sh plant     load rows into pii_canary_us.{customers,orders,events} and pii_canary_eu.patients
#   ./validation/plant.sh clear     truncate those tables
set -euo pipefail
P="${PROJECT_ID:-claude-code-507112}"
load() { # <dataset.table> <csv text>
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' RETURN
  printf '%s\n' "$2" > "$tmp"
  bq load --project_id="$P" --replace --skip_leading_rows=1 --source_format=CSV --allow_quoted_newlines "$P:$1" "$tmp" >/dev/null
}
case "${1:-}" in
  plant)
    load pii_canary_us.customers 'customer_id,full_name,email,phone,ssn,card_number,signup_ip,contact_info,plan
1,Alice Nguyen,alice.nguyen@example.com,(415) 555-2671,078-05-1120,4111 1111 1111 1111,8.8.8.8,alice.n@example.com,pro
2,Bob Okafor,bob.okafor@example.org,(212) 555-0187,219-09-9999,5500 0000 0000 0004,1.1.1.1,bob.o@example.org,free
3,Carol Silva,carol.silva@example.net,(303) 555-0142,123-45-6789,3400 0000 0000 009,9.9.9.9,carol.s@example.net,pro
4,Dan Petrov,dan.petrov@example.io,(206) 555-0199,457-55-5462,6011 0000 0000 0004,208.67.222.222,dan.p@example.io,team'
    load pii_canary_us.orders 'order_id,customer_id,total,status,sku_code
101,1,19.99,shipped,SKU-1001
102,2,5.50,pending,SKU-2002
103,3,120.00,delivered,SKU-3003'
    load pii_canary_us.events 'event_id,is_credit_card,payment_type,latency_ms
e1,true,card,120.5
e2,false,cash,98.1
e3,true,card,140.2'
    load pii_canary_eu.patients 'patient_id,email,iban,birth_date,visit_note
1,pat.one@example.com,GB82 WEST 1234 5698 7654 32,1980-04-12,routine checkup
2,pat.two@example.org,DE89 3704 0044 0532 0130 00,1975-11-02,follow up
3,pat.three@example.net,FR14 2004 1010 0505 0001 3M02 606,1990-07-23,lab results'
    echo "loaded fake rows into the canary tables";;
  clear)
    for t in pii_canary_us.customers pii_canary_us.orders pii_canary_us.events pii_canary_eu.patients; do bq query --project_id="$P" --use_legacy_sql=false "TRUNCATE TABLE \`$P.$t\`" >/dev/null; done
    echo "cleared";;
  *) echo "usage: $0 plant|clear"; exit 2;;
esac
