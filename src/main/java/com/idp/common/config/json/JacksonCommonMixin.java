package com.idp.common.config.json;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY
			, getterVisibility = JsonAutoDetect.Visibility.NONE
			, isGetterVisibility = JsonAutoDetect.Visibility.NONE)
public abstract class JacksonCommonMixin {
	@JsonCreator
	JacksonCommonMixin(@JsonProperty("value") String value) {}
}
