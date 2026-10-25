import type { IncomingMessage, ServerResponse } from 'node:http';
/** Harness master resource routes also serve trusted in-process Peer reads. */
export type WebResource = (request: Request, peer?: object) => Promise<Response>;
/** Forward a Fetch response with backpressure and cancellation on disconnect. */
export declare function serveResource(request: IncomingMessage, response: ServerResponse, resource: WebResource): Promise<void>;
//# sourceMappingURL=web-resource.d.ts.map