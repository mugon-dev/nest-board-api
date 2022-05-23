import { Module } from '@nestjs/common';
import { BoardsModule } from './boards/boards.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { typeormConfig } from './configs/typeorm.config';

@Module({
  imports: [TypeOrmModule.forRoot(typeormConfig), BoardsModule],
})
export class AppModule {}
