import {BadRequestException,Injectable,UnauthorizedException} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    
    constructor(@InjectModel(User.name) private UserModel: Model<User>,
                private jwtService:JwtService,
            ){}

    async signup(signupData: SignupDto){

        const {email,password,name} = signupData;

        // Email Check
        const currEmail = await this.UserModel.findOne({
            email,
        });
        if(currEmail){
            throw new BadRequestException('Email already Exsists!');
        }

        // Password 
        const hashedPassword = await bcrypt.hash(password,10);

        // Create
        await this.UserModel.create({
            name,
            email,
            password:hashedPassword,
        })
    }
    async login(loginData: LoginDto){

        const {email,password} = loginData;

        // Email Check
        const user = await this.UserModel.findOne({
            email,
        });
        if(!user){
            throw new UnauthorizedException('Wrong Credentials!');
        }

        // Password 
        const passwordMatch = await bcrypt.compare(password,user.password);
        if(!passwordMatch){
            throw new UnauthorizedException('Wrong Credentials!');
        }
        
        return this.generateUserTokens(user._id);
    }

    async generateUserTokens(userId){
        // Generate JWT Token
        const accessToken= this.jwtService.sign({userId},{expiresIn:'1h'});
        
        return{
            accessToken,
        };
    }
}
