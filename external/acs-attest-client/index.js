/*
Copyright (c) 2025 Alibaba Cloud

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


import axios from 'axios';
import jsonwebtoken from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { jwtDecode } from 'jwt-decode';
import { attest_adr,verify_adr, typeflag } from '../../src/lib/stores/index.ts';

let ATTEST_SERVICE_ENDPOINT;
let verifyToken;
let ast_type;
attest_adr.subscribe(value => (ATTEST_SERVICE_ENDPOINT = value));
verify_adr.subscribe(value => (verifyToken = value));
typeflag.subscribe(value => (ast_type =value));

export async function attest(quote) {
	const quotebase64 = Buffer.from(quote).toString('base64');
	const evidence = {
		"quote": quotebase64,
		"aa_eventlog": null,
		"cc_eventlog": null,
	};

	// base64 encode evidence with URL safe characters without padding
	const evidencebase64 = Buffer.from(JSON.stringify(evidence)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

	const req = {
		// empty policy_ids means only check the cryptographic integrity of the evidence
		"tee": "tdx",
		"evidence": evidencebase64,
		"policy_ids": [],
	}
	console.log("CHECK ATTEST_address: ", ATTEST_SERVICE_ENDPOINT);
	console.log("CHECK ATTEST_type: ", ast_type);
	const response = await axios.post(ATTEST_SERVICE_ENDPOINT, req);
	return response.data;
}

export async function decode_apprasial_token(token) {
	const decoded = jwtDecode(token);

	return decoded;
}

export async function verify_apprasial_token(token) {
	const client = jwksClient({
		// jwksUri: 'https://attest.cn-beijing.aliyuncs.com/jwks.json',
		jwksUrl: verifyToken
	});
	const key = await client.getSigningKey();
	const publicKey = key.getPublicKey();

	const decoded = jsonwebtoken.verify(token, publicKey);

	return decoded;
}


