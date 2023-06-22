import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import {} from 'express-async-errors';
import * as userRepository from '../data/auth.js';

export const jwtSecretKey = process.env.JWT_SECRET;
export const csrf_secret_key = process.env.CSRF_SECRET;

const jwtExpiresInDays = process.env.JWT_EXPIRES_SEC;
const bcryptSaltRounds = process.env.BCRYPT_SALT_ROUNDS;

/** 회원가입 */
export async function signup(req, res) {
  const { username, password, nickname, email, url } = req.body;
  const found = await userRepository.findByUsername(username);

  if (found) {
    return res.status(409).json({ message: `${username} already exists` });
  }
  const hashed = bcrypt.hash(password, bcryptSaltRounds);
  const userId = await userRepository.createUser({
    username,
    password: hashed,
    nickname: nickname ?? '',
    email,
    ismanage,
  });

  const token = createJwtToken(userId);
  setToken(res, token);
  res.status(201).json({ token, username });
}

/** 로그인 */
export async function login(req, res) {
  const { username, password } = req.body;
  const user = await userRepository.findByUsername(username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid user or password' });
  }
  //compare를 통해 암호화전과 암호화후의 비밀번호를 비교할수있음
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(401).json({ message: 'Invalid user or password' });
  }

  const token = createJwtToken(user.id);
  setToken(res, token);
  res.status(200).json({ token, username });
}

/** 로그아웃 */
export async function logout(req, res, next) {
  res.cookie('token', '');
  res.status(200).json({ message: 'User has been logged out' });
}

function createJwtToken(id) {
  return jwt.sign({ id }, jwtSecretKey, { expiresIn: jwtExpiresInDays });
}

function setToken(res, token) {
  const options = {
    maxAge: jwtExpiresInDays * 1000,
    httpOnly: true,
    sameSite: 'none', //CORS 설정과 비슷하게 서버와 다른 도메인을 가진 client를 허용해주는 옵션설정이다
    secure: true,
  };

  res.cookie('token', token, options); //HTTP-ONLY
}

export async function me(req, res, next) {
  //isAuth 미들웨어에서 만들어준 userId를 이용하고있음
  const user = await userRepository.findById(req.userId);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.status(200).json({
    //이렇게 req Header의 Auth정보를 뽑을수도있다.
    // token: req.get('Authorization').split(' ')[1],
    token: req.token,
    username: user.username,
  });
}

export async function csrfToken(req, res, next) {
  const csrfToken = await generateCSRFToken();
  res.status(200).json({ csrfToken });
}

async function generateCSRFToken() {
  return bcrypt.hash(csrf_secret_key, 1);
}
