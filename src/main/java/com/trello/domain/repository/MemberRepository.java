package com.trello.domain.repository;

import org.springframework.data.repository.CrudRepository;
import com.trello.domain.Member;

public interface MemberRepository extends CrudRepository<Member, Long> {
	 public Member findByUemail(String email);
}
