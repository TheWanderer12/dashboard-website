import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);
        console.log("credentials parsed.");
        if (parsedCredentials.success) {
          console.log('parsed credentials successful.')
          const { email, password } = parsedCredentials.data;

          console.log(`email from credentials:${email}`);
          console.log(`password from credentials:${password}`);

          const user = await getUser(email);

          if (!user) return null;
          console.log(`email from user:${user.email}`);
          console.log(`password from user:${user.password}`);
          const passwordsMatch = await bcrypt.compare(password, user.password);
          console.log(`did passwords match?${passwordsMatch}`);
          if (passwordsMatch) return user;
        }

        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});