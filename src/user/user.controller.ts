import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { Request } from 'express';
import { MyJwtGuard } from 'src/auth/guard';

@Controller('users')
export class UserController {
      @UseGuards(MyJwtGuard)
      @Get('me')
      me(@Req() request: Request) {
            return request.user
      }
}
