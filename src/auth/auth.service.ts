// src/auth/auth.service.ts
import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../user/user.service';
import { CreateUserDto } from '../user/create-user.dto'; // DIPERBAIKI PATH
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { User, UserRole } from '../user/user.entity';

// ... (sisa AuthService tetap sama) ...
export interface JwtPayload {
  sub: number; // User ID
  username: string;
  role: UserRole; // Sertakan role di payload JWT
}

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    // private configService: ConfigService, // Jika JWT_SECRET diambil dari sini
  ) {}

  async validateUser(email: string, pass: string): Promise<Omit<User, 'passwordHash'> | null> {
    const user = await this.usersService.findOneByEmail(email);
    if (user && user.passwordHash && await bcrypt.compare(pass, user.passwordHash)) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { passwordHash, ...result } = user; // Jangan kembalikan hash password
      return result;
    }
    return null;
  }

  async register(createUserDto: CreateUserDto) {
    // Cek apakah email atau username sudah ada
    const existingUserByEmail = await this.usersService.findOneByEmail(createUserDto.email);
    if (existingUserByEmail) {
      throw new BadRequestException('Email sudah terdaftar.');
    }
    const existingUserByUsername = await this.usersService.findOneByUsername(createUserDto.username);
    if (existingUserByUsername) {
      throw new BadRequestException('Username sudah terdaftar.');
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // Backend menentukan role, bukan frontend untuk registrasi publik
     const userToCreateData = { // Pastikan ini sesuai dengan parameter metode create di UsersService
      username: createUserDto.username,
      email: createUserDto.email,
      passwordHash: hashedPassword,
      role: 'user' as UserRole,
    };

    const newUser = await this.usersService.create(userToCreateData);

    const payload: JwtPayload = {
        username: newUser.username,
        sub: newUser.id,
        role: newUser.role, // Sertakan role di payload JWT
    };

    return {
      access_token: await this.jwtService.signAsync(payload),
      user: { // Kirim data user yang relevan ke frontend
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
      },
    };
  }

  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.email, loginDto.password);
    if (!user) {
      throw new UnauthorizedException('Email atau password salah.');
    }

    const payload: JwtPayload = {
        username: user.username,
        sub: user.id,
        role: user.role, // Pastikan role ada di objek user dari validateUser
    };

    return {
      access_token: await this.jwtService.signAsync(payload),
      user: { // Kirim data user yang relevan ke frontend
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    };
  }
}