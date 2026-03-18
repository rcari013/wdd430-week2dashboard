import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import postgres from 'postgres';
import bcrypt from 'bcrypt';
import { authConfig } from './auth.config';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string) {
  try {
    const users = await sql`SELECT * FROM users WHERE email = ${email}`;
    return users[0];
  } catch (error) {
    console.error('Database fetch failed:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut, handlers } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        console.log('Raw credentials:', credentials);

        const parsedCredentials = z
          .object({
            email: z.string().email(),
            password: z.string().min(6),
          })
          .safeParse(credentials);

        console.log('Parsed credentials success:', parsedCredentials.success);

        if (!parsedCredentials.success) {
          console.log('Validation failed');
          return null;
        }

        const { email, password } = parsedCredentials.data;
        console.log('Email being checked:', email);

        const user = await getUser(email);
        console.log('User from DB:', user);

        if (!user) {
          console.log('No user found');
          return null;
        }

        const passwordsMatch = await bcrypt.compare(password, user.password);
        console.log('Password match:', passwordsMatch);

        if (passwordsMatch) return user;

        return null;
      },
    }),
  ],
});