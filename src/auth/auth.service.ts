import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDTO) {
    try {
      // generate the password hash
      const hash = await argon.hash(dto.password);
      // save the new user in db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      // return the saved user token
      return this.signToken(user.email, user.id);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async login(dto: AuthDTO) {
    // find the email in db
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if missing then throw exception
    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }
    // verify the password
    const pwdMatch = await argon.verify(user.hash, dto.password);
    //if doesnt matches, throw exceprion
    if (!pwdMatch) {
      throw new ForbiddenException('Invalid credentials');
    }
    //if all goes well, return user token
    return this.signToken(user.email, user.id);
  }

  async signToken(
    email: string,
    userId: number,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      secret: secret,
      expiresIn: '15m',
    });

    return {
      access_token: token,
    };
  }
}
