import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { User } from "@prisma/client"
import { AuthDTO } from "./dto";
import * as argon from 'argon2'
import { JwtService } from "@nestjs/jwt/dist";
import { ConfigService } from "@nestjs/config/dist/config.service";

@Injectable({})
export class AuthService {
      constructor(
            private prismaService: PrismaService,
            private jwtService: JwtService,
            private configService: ConfigService
      ) {}
      async register(authDTO: AuthDTO) {
            // generate password to hashedPassword
            const hashedPassword = await argon.hash(authDTO.password)
            try {
                  // insert data to database 
                  const user = await this.prismaService.user.create({
                        data: {
                              email: authDTO.email,
                              hashedPassword: hashedPassword,
                              firstName: '',
                              lastName: ''
                        },
                        select: {
                              id: true,
                              email: true,
                              createdAt: true
                        }
                  })
                  return await this.signJwtToken(user.id, user.email)
            } catch (err) {
                  if (err.code == 'P2002') {
                        throw new ForbiddenException('Error in credentials')
                  }
            }
      }
      async login(authDTO: AuthDTO) {
            const user = await this.prismaService.user.findUnique({
                  where: {
                        email: authDTO.email
                  }
            })
            if(!user) {
                  throw new ForbiddenException('User not found')
            }
            const passwordMatched = await argon.verify(
                  user.hashedPassword,
                  authDTO.password
            )
            if(!passwordMatched) {
                  throw new ForbiddenException('Incorrect password')
            }
            delete user.hashedPassword
            return await this.signJwtToken(user.id, user.email)
      }
      async signJwtToken(userId: number, email: string): Promise<{accessToken: string}> {
            const payload = {
                  sub: userId,
                  email: email,
            }
            const jwtString = await this.jwtService.signAsync(payload, {
                  expiresIn: '10m',
                  secret: this.configService.get('JWT_SECRET')
            })
            return {
                  accessToken: jwtString,
            }
      }
}