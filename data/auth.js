//2.sequel 사용
import SQ from 'sequelize';
import { sequelize } from '../db/databaseSequel.js';
const DataTypes = SQ.DataTypes;

//sequelize 사용 시 user 테이블 만드는 코드, users테이블이 존재하지 않을때만 테이블을 만든다!! 이미 존재한다면 define은 실행되지 않는다.
//고로 테이블 컬럼을 바꾸고 싶으면 mysql 워크벤치에서 테이블 삭제하고 해당 코드 실행시켜야함!!!
export const User = sequelize.define(
  'users',
  {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      allowNull: false,
      primaryKey: true,
    },
    username: {
      type: DataTypes.STRING(45),
      allowNull: false,
    },
    password: {
      type: DataTypes.STRING(128),
      allowNull: false,
    },
    nickname: {
      type: DataTypes.STRING(128),
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING(128),
      allowNull: false,
    },
    ismanage: DataTypes.BOOLEAN,
  },
  {
    //자동으로 생성되는 createAt, updateAt을 삭제할수있음
    timestamps: false,
  }
);

//특정유저의 이름에 매칭되는 레코드 뽑아오기
export async function findByUsername(username) {
  //<Sequelize>
  //컬럼의 username과 인자로 받은 username이 같은 레코드를 찾는 조건
  //알아서 찾은 데이터를 return 해주기떄문에 순수 SQL처럼 return[0][0]이렇게 안해도됨
  return User.findOne({ where: { username: username } });
}

//특정유저의 고유한 id에 매칭되는 레코드 뽑아오기
export async function findById(id) {
  //<Sequelize>
  //User table의 프라이머리키를 기준으로 레코드를 뽑을때 쓰는 함수임
  return User.findByPk(id);
}

//새로운 유저 추가하기
export async function createUser(user) {
  //<Sequelize>
  //추가한 데이터의 주요키가 dataValues.id로 반환된다
  return User.create(user).then(data => {
    return data.dataValues.id;
  });
}
