import { defineEventHandler } from 'h3';
import { getUsers } from '~/lib/db';

// VULNERABLE: raw User[] returned from a Nuxt server route — password_hash,
// api_key, ssn all land in __NUXT_DATA__ and are visible to any HTTP client.
export default defineEventHandler(async () => {
  return await getUsers();
});
