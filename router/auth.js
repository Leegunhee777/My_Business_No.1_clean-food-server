import express from 'express';
import {} from 'express-async-errors';
import { body } from 'express-validator';
import { validate } from '../middleware/validator.js';
import * as authController from '../controller/auth.js';
import { isAuth } from '../middleware/auth.js';

const router = express.Router();

const validateCredential = [
  body('username')
    .trim()
    .notEmpty()
    .withMessage('username should be at least 5 characters'),
  body('password')
    .trim()
    .isLength({ min: 5 })
    .withMessage('password should be at least 5 characters'),
  validate,
];

const validateSignup = [
  ...validateCredential,
  body('nickname').optional({
    //보내지 않는것도 허용
    nullable: true,
    //빈 값을 보내도 허용
    checkFalsy: true,
  }),
  body('email').isEmail().normalizeEmail().withMessage('invalid email'),

  validate,
];

router.post('/signup', validateSignup, authController.signup);
router.post('/login', validateCredential, authController.login);
router.post('/logout', authController.logout);

//me라는 api는 사용자 검증이 필요한 api이다.
router.get('/me', isAuth, authController.me);

//CSRF 어택 방지를 위한 처리
router.get('/csrf-token', authController.csrfToken);

export default router;
