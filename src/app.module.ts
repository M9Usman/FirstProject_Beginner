import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import config from './config/config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal:true,
      cache:true,
      load:[config],
    }),
    AuthModule, 
    MongooseModule.forRootAsync({
      imports:[ConfigModule],
      useFactory:async(config)=>({
        uri:config.get('database.connectionString'),
      }),
      inject:[ConfigService],
    }),
    JwtModule.registerAsync({
      imports:[ConfigModule],
      useFactory:async(config)=>({
        secret:config.get('jwt.secret'),
      }),
      global:true,
      inject:[ConfigService]
    })],
    controllers: [AppController],
    providers: [AppService],
}) 
export class AppModule {

}