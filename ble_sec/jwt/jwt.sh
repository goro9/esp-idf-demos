#!/bin/bash

secret=ae2cb33495a55f11a9f15ecb1e53cc7eeb7b4c61f000cf214277cab1136bcab6

header={"alg":"HS256","typ":"JWT"}
header=$(echo -n $header | base64)

iat=$(date +%s)
payload={"iat":${iat}}
payload=$(echo -n $payload | base64)

token_without_signature=$(echo -n $header.$payload)
signature=$(echo -n $token_without_signature | openssl dgst -binary -sha256 -hmac $secret | base64)
token=$(echo -n $token_without_signature.$signature)

echo $token