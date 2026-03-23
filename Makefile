name := secure-api-gateway-fapi-pep-as
repo := europe-west4-docker.pkg.dev/sbat-gcr-develop/sapig-docker-artifact
service := fapi-pep-as
latesttagversion := latest
helm_repo := forgerock-helm/secure-api-gateway/${name}/

clean:
	mvn clean

docker: clean
ifndef tag
	$(warning no tag supplied; latest assumed)
	$(eval TAG=latest)
else
	$(eval TAG=$(shell echo $(tag) | tr A-Z a-z))
endif
ifndef setlatest
	$(warning no setlatest true|false supplied; false assumed)
	$(eval setlatest=false)
endif
ifndef mavenArgs
	$(warning no mavenArgs supplied;)
	$(eval mavenArgs=)
endif
ifndef env
	$(warning no env supplied; prod assumed)
	$(eval env=prod)
endif
	@if [ "${setlatest}" = "true" ]; then \
  		mvn package docker:push -Pdocker-build -Ddocker.image.repo=${repo}/securebanking -Ddocker.image.name=${service} -Ddocker.image.tag=${TAG} -Ddocker.tags.1=${latesttagversion} -Dtarget.env=${env} ${mavenArgs};\
    else \
        mvn package docker:push -Pdocker-build -Ddocker.image.repo=${repo}/securebanking -Ddocker.image.name=${service} -Ddocker.image.tag=${TAG} -Dtarget.env=${env} ${mavenArgs};\
   	fi;

package_helm:
ifndef version
	$(error A version must be supplied, Eg. make helm version=1.0.0)
endif
	helm dependency update _infra/helm/${name}
	helm template _infra/helm/${name}
	helm package _infra/helm/${name} --version ${version} --app-version ${version}

publish_helm:
ifndef version
	$(error A version must be supplied, Eg. make helm version=1.0.0)
endif
	jf rt upload  ./*-${version}.tgz ${helm_repo}