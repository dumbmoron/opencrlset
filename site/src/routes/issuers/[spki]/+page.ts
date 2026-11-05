import { error } from "@sveltejs/kit";
import * as data from "#lib/data.ts";

export const load = async ({ params, parent }) => {
  const [detail, bySpki, { meta }] = await Promise.all([
    data.issuer(params.spki),
    data.issuersBySpki(),
    parent(),
  ]);

  if (!detail) error(404, `No issuer with key ${params.spki} in this build.`);
  const blocked = meta.blockedKeys.find((key) => key.spkiSha256 === params.spki);

  return {
    detail,
    summary: bySpki.get(params.spki),
    blocked,
    blockedBy: blocked && bySpki.get(blocked.issuer),
  };
};
