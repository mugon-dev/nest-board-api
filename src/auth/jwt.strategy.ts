import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { UserRepository } from './user.repository';
import { User } from './user.entity';

@Injectable()
// @Injectable => jwt strategy 를 다른 곳에서도 사용하기 위해
// Nest.js can inject it anywhere this service is needed
// via its Dependency Injection system
export class JwtStrategy extends PassportStrategy(Strategy) {
  // the class extends the PassportStrategy class defined by @nestjs/passport package
  // you're passing the JWT Strategy defined by the passport-jwt
  constructor(
    // user 확인하기 위해 repository 를 주입받음
    @InjectRepository(UserRepository)
    private userRepository: UserRepository,
  ) {
    // passes two important options
    super({
      secretOrKey: 'Secret1234',
      // This configures the secret key that JWT Strategy will use
      // to decrypt the JWT token in order to validate it
      // and access its payload
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // This configures the Strategy (imported from passport-jwt)
      // to look for the JWT in the Authorization Header of the current Request
      // passed over as a Bearer token
    });
  }

  // 위에서 토큰이 유효한지 체크가 되면 validate 메소드에서 payload 에 있는 유저이름이 데이터베이스에서
  // 있는 유저인지 확인 후 있다면 유저 객체를 return 값으로 던져줌
  // return 값은 @UseGuards(AuthGuard())를 이용한 모든 요청의 Request Object 에 들어감
  async validate(payload) {
    const { username } = payload;
    const user: User = await this.userRepository.findOne({ username });
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
