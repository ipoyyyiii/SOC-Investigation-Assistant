#!/bin/bash
TOK=$(curl -s -m 15 -X POST http://127.0.0.1:8081/realms/master/protocol/openid-connect/token \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password='REPLACE_KEYCLOAK_ADMIN_PASS' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -m 15 -H "Authorization: Bearer $TOK" \
  "http://127.0.0.1:8081/admin/realms/soc/events?type=LOGIN&type=LOGIN_ERROR&max=50"
