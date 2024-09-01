package com.example.springjwt.repository;

import com.example.springjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> { //db 접속 레퍼지토리

    Boolean existsByUsername(String username);

    //username을 DB테이블에서 회원 조회 메소드 작성
    UserEntity findByUsername(String username);

}
