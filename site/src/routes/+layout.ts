import * as data from "#lib/data.ts";

export const load = async () => ({ meta: await data.meta() });
