import { Controller, Post,Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService){}

    // TODO: POST Signup
    @Post('/signup') //auth/signup
    async signUp(@Body() signupData: SignupDto) {
        return this.authService.signup(signupData);
    }
    // TODO: POST LOGIN
    @Post('/login') //auth/signup
    async login(@Body() credential: LoginDto) {
        return this.authService.login(credential);
    }
    // TODO: POST Refresh Token
}
