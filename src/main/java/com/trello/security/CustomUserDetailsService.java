package com.trello.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.trello.domain.repository.MemberRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService{
	

	@Autowired
	MemberRepository memberRepository;
	
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		return
				memberRepository.findByUemail(email)
				.filter(m -> m!= null)
				.map(m -> new SecurityMember(m)).get();
	}

}
