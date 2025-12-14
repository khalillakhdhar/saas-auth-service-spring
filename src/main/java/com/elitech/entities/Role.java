package com.elitech.entities;

import java.util.HashSet;
import java.util.Set;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer","handler"})
public class Role {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
private long id;
	String name;
	@ManyToMany(mappedBy = "roles",fetch = FetchType.LAZY)
	private Set<UserInfo> users=new HashSet<UserInfo>();
	
	
}
