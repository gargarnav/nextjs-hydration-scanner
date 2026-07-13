import { defineEventHandler } from 'h3';
import { getUsers } from '~/lib/db';
import { toPublicUsers } from '~/lib/dto';

// SECURE: DTO applied before returning — sensitive fields never leave the server.
export default defineEventHandler(async () => {
  return toPublicUsers(await getUsers());
});
