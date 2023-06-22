import { csrf_secret_key } from '../controller/auth.js';
import bcrypt from 'bcrypt';
export const csrfCheck = (req, res, next) => {
  if (
    //무엇인가 변경하는것이 아닌 method는 굳이 검증이 필요없다.
    req.method === 'GET' ||
    req.method === 'OPTIONS' ||
    req.method === 'HEAD'
  ) {
    return next();
  }
  //req.get() 함수는 대소문자를 구분하지 않는 지정된 HTTP 요청 헤더의 특정 필드를 반환한다.
  // 고유한도메인이름-custom-header 이런식의 네이밍으로 Header의 필드를 지정하는게 좋다
  const csrfHeader = req.get('greenary-csrf-token');

  if (!csrfHeader) {
    console.warn(
      `Missing required "greenary-csrf-token" header.`,
      req.header.origin
    );
    return res.status(403).json({ message: 'Failed CSRF check' });
  }

  validateCsrfToken(csrfHeader)
    .then(valid => {
      if (!valid) {
        console.warn(
          `Missing provided in "greenary-csrf-token" header does not validate`,
          req.header.origin,
          csrfHeader
        );
        return res.status(403).json({ message: 'Failed CSRF check' });
      }
      next();
    })
    .catch(err => {
      console.log(err);
      return res.status(500).json({ message: 'Something went wrong' });
    });
};

async function validateCsrfToken(csrfHeader) {
  return bcrypt.compare(csrf_secret_key, csrfHeader);
}
