import rateLimit from 'express-rate-limit';

//fixed Window로 각 IP 당 1분동안에 100번의 request를 허용한다고 설정함
export default rateLimit({
  windowMs: 60000,
  //max를 통해 각 IP당 1분동안 얼마나 많은 request를 할수있는지 지정해주고있다.
  max: 100,
});
