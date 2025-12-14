package com.elitech.services;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.elitech.entities.Role;
import com.elitech.entities.UserInfo;
import com.elitech.repositories.RoleRepository;
import com.elitech.repositories.UserInfoRepository;
@Service
public class UserInfoService implements UserDetailsService {
	@Autowired
	private UserInfoRepository userInfoRepository;
	@Autowired
	private RoleRepository roleRepository;
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		Optional<UserInfo> userInfo=userInfoRepository.findByEmail(username);
		return userInfo.map(UserInfoDetails::new)
				.orElseThrow(()-> new UsernameNotFoundException("User not found with email "+username));
	}
	public UserInfo getUserByEmail(String email)
	{
		return userInfoRepository.findByEmail(email).orElse(null);
		
	}
	public UserInfo addOneUser(UserInfo userInfo)
	{
		userInfo.setPassword(passwordEncoder.encode(userInfo.getPassword()));
		Set<Role> managedRoles=new HashSet<>();
		for(Role role : userInfo.getRoles() )
		{
			Role manageRole=roleRepository.findById(role.getId())
					.orElseThrow(()-> new RuntimeException("Role not found "+role.getId()));
			managedRoles.add(manageRole);
		}
		userInfo.setRoles(managedRoles);
		System.out.println("roles assigned "+managedRoles);
		return userInfoRepository.save(userInfo);
	}
public List<UserInfo> getAllUser()
{
return userInfoRepository.findAll();	
}
public UserInfo getOneUser(long id)
{
return userInfoRepository.findById(id).orElse(null);	
}
public void deleteOneUser(long id)
{
userInfoRepository.deleteById(id);	

}


}
