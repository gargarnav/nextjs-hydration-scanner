import type { PageServerLoad } from './$types';
import { getUsers } from '$lib/db';
import { toPublicUsers } from '$lib/dto';

// SECURE: DTO applied before returning — sensitive fields stripped.
export const load: PageServerLoad = async () => {
  const users = await getUsers();
  return { users: toPublicUsers(users) };
};
