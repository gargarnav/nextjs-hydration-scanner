import type { PageServerLoad } from './$types';
import { getUsers } from '$lib/db';

// VULNERABLE: raw User[] is returned from load() — password_hash, api_key, ssn
// all land in window.__sveltekit_data and are visible to any HTTP client.
export const load: PageServerLoad = async () => {
  const users = await getUsers();
  return { users };
};
