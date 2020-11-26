#!/bin/bash

harborUsername='xxx'
harborPassword='xxx'
newHarborRegistry='xxx'

harborBasicAuthToken=$(echo -n "${harborUsername}:${harborPassword}" | base64)

docker login --username ${harborUsername} --password ${harborPassword} ${newHarborRegistry}

# initialization
initialize_migrator() {
	# sets colors for use in output
	GREEN='\e[32m'
	BLUE='\e[34m'
	YELLOW='\e[0;33m'
	RED='\e[31m'
	BOLD='\e[1m'
	CLEAR='\e[0m'

	# pre-configure ok, warning, and error output
	OK="[${GREEN}OK${CLEAR}]"
	INFO="[${BLUE}INFO${CLEAR}]"
	NOTICE="[${YELLOW}!!${CLEAR}]"
	ERROR="[${RED}ERROR${CLEAR}]"
}

restore_harbor_data () {
	pushd $RESTORE_DIR/harbor
	while IFS="" read -r image || [ -n "$image" ]
	do
		projName=${image%%/*}
		# echo ${projName}
		echo -e "${INFO} Start to upload harbor project: $projName images..."
		# create harbor project
		curl -k -X POST -H "Authorization: Basic ${harborBasicAuthToken}" "https://${newHarborRegistry}/api/projects" -H "accept: application/json" -H "Content-Type: application/json" -d '{ "project_name": "'"$projName"'", "metadata": { "public": "true" }}'
		# load image
		flag=0
		for ((i=1; i<=10; i++))
		do
			docker load -i dist/${image}.tar
			if [ $? -eq 0 ]
			then
				echo -e "${INFO} load image: ${image} successfully"
				flag=1
				break
			else
				echo -e "${ERROR} load image: ${image} failure"
			fi
		done
		# record image to failure list file
		if [ $flag -eq 0 ]
		then
			echo "${image}" >> dist/images_restore_failure.list
			continue
		fi

		# tag image
		flag=0
		for ((i=1; i<=10; i++))
		do
			docker tag ${image} ${newHarborRegistry}/${image}
			if [ $? -eq 0 ]
			then
				echo -e "${INFO} tag image: ${image} successfully"
				flag=1
				break
			else
				echo -e "${ERROR} tag image: ${image} failure"
			fi
		done
		# record image to failure list file
		if [ $flag -eq 0 ]
		then
			echo "${image}" >> dist/images_restore_failure.list
			continue
		fi

		# push image
		flag=0
		for ((i=1; i<=10; i++))
		do
			docker push ${newHarborRegistry}/${image}
			if [ $? -eq 0 ]
			then
				echo -e "${INFO} push image: ${image} successfully"
				flag=1
				break
			else
				echo -e "${ERROR} push image: ${image} failure"
			fi
		done
		# record image to failure list file
		if [ $flag -eq 0 ]
		then
			echo "${image}" >> dist/images_restore_failure.list
			continue
		fi

		echo -e "${INFO} Upload harbor image: ${image} completed\n"
	done < dist/images.list

	while IFS="" read -r chart || [ -n "$chart" ]
	do
		projName=${chart%%/*}
		# echo ${projName}
		echo -e "${INFO} Start to upload harbor project: $projName charts..."
		# create harbor project
		curl -k -X POST -H "Authorization: Basic ${harborBasicAuthToken}" "https://${newHarborRegistry}/api/projects" -H "accept: application/json" -H "Content-Type: application/json" -d '{ "project_name": "'"$projName"'", "metadata": { "public": "true" }}'
		# upload chart
		flag=0
		for ((i=1; i<=10; i++))
		do
			ret=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" -X POST "https://${newHarborRegistry}/api/chartrepo/${projName}/charts" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "chart=@dist/${chart};type=application/gzip"`
			if [ $ret == "{\"saved\":true}" ]; then
				flag=1
				break
			else
				echo -e "${ERROR} upload chart: ${chart} failure"
			fi
		done
		# record chart to failure list file
		if [ $flag -eq 0 ]
		then
			echo "${projName}:${durl}" >> dist/charts_restore_failure.list
			continue
		fi

		echo -e "${INFO} upload chart: ${chart} completed\n"
	done < dist/charts.list

	popd
}

main() {
	initialize_migrator
	RESTORE_DIR=$1
	restore_harbor_data
}

main "$@"
