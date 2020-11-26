#!/bin/bash

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

prepare_backup_dir() {
	echo -e "${INFO} Start to clear harbor backup directory ..."
	rm -rf $BACKUP_DIR/harbor
	mkdir -p $BACKUP_DIR/harbor
}

backup_harbor_data() {
	pushd $BACKUP_DIR/harbor

	harborUsername='xxx'
	harborPassword='xxx'
	oldHarborRegistry='xxx'
	harborBasicAuthToken=$(echo -n "${harborUsername}:${harborPassword}" | base64)

	docker login --username ${harborUsername} --password ${harborPassword} ${oldHarborRegistry}

	rm -f dist/images.list
	rm -f dist/charts.list

	# list projects
	projs=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${oldHarborRegistry}"'/api/projects?page=1&page_size=1000' | jq -r '.[] | "\(.project_id)=\(.name)"'`
	for proj in ${projs[*]}; do
		projId=`echo $proj|cut -d '=' -f 1`
		projName=`echo $proj|cut -d '=' -f 2`

		echo -e "${INFO} Start to download harbor project: $projName images..."

		# list repos in one project
		repos=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${oldHarborRegistry}"'/api/repositories?page=1&page_size=1000&project_id='"${projId}" | jq -r '.[] | "\(.id)=\(.name)"'`
		for repo in ${repos[*]}; do
			repoId=`echo $repo|cut -d '=' -f 1`
			repoName=`echo $repo|cut -d '=' -f 2`
			echo -e "${INFO} Start to download harbor repo: $repoName images..."
			# list tags in one repo
			tags=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${oldHarborRegistry}"'/api/repositories/'"${repoName}"'/tags?detail=1' | jq -r '.[].name'`
			for tag in ${tags[*]}; do
				# pull image
				flag=0
				for ((i=1; i<=10; i++))
				do
					docker pull ${oldHarborRegistry}/${repoName}:${tag}
					if [ $? -eq 0 ]
					then
						echo -e "${INFO} pull image: ${repoName}:${tag} successfully"
						flag=1
						break
					else
						echo -e "${ERROR} pull image: ${repoName}:${tag} failure"
					fi
				done
				# record image to failure list file
				if [ $flag -eq 0 ]
				then
					echo "${repoName}:${tag}" >> dist/images_failure.list
					continue
				fi

				# tag image
				flag=0
				for ((i=1; i<=10; i++))
				do
					docker tag ${oldHarborRegistry}/${repoName}:${tag} ${repoName}:${tag}
					if [ $? -eq 0 ]
					then
						echo -e "${INFO} retag image: ${repoName}:${tag} successfully"
						flag=1
						break
					else
						echo -e "${ERROR} retag image: ${repoName}:${tag} failure"
					fi
				done
				# record image to failure list file
				if [ $flag -eq 0 ]
				then
					echo "${repoName}:${tag}" >> dist/images_failure.list
					continue
				fi

				# save image
				flag=0
				for ((i=1; i<=10; i++))
				do
					mkdir -p $(dirname dist/${repoName})
					docker save -o dist/${repoName}:${tag}.tar	${repoName}:${tag}
					if [ $? -eq 0 ]
					then
						echo -e "${INFO} save image: ${repoName}:${tag} successfully"
						flag=1
						break
					else
						echo -e "${ERROR} save image: ${repoName}:${tag} failure"
					fi
				done
				# record image to failure list file
				if [ $flag -eq 0 ]
				then
					echo "${repoName}:${tag}" >> dist/images_failure.list
					continue
				fi

				# record image to list file
				echo "${repoName}:${tag}" >> dist/images.list
				echo -e "${INFO} download image: ${repoName}:${tag} completed\n"
			done
		done

		# list charts in one project
		charts=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${oldHarborRegistry}"'/api/chartrepo/'"${projName}"'/charts' | jq -r '.[].name'`
		for chart in ${charts[*]}; do
			# list download urls in one chart
			durls=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${oldHarborRegistry}"'/api/chartrepo/'"${projName}"'/charts/'"${chart}" | jq -r '.[].urls[0]'`
			#echo ${durl[*]}
			for durl in ${durls[*]}; do
				echo -e "${INFO} start to download project: ${projName} charts ..."
				# download chart
				mkdir -p $(dirname dist/${projName}/${durl})
				flag=0
				for ((i=1; i<=10; i++))
				do
					ret=`curl -s -k -w "%{http_code}" -H "Authorization: Basic ${harborBasicAuthToken}" -o dist/${projName}/${durl} "https://${oldHarborRegistry}/chartrepo/${projName}/${durl}"`
					if [ $ret == "200" ]; then
						flag=1
						break
					else
						echo -e "${ERROR} download chart: ${projName}/${durl} failure"
					fi
				done
				# record chart to failure list file
				if [ $flag -eq 0 ]
				then
					echo "${projName}:${durl}" >> dist/charts_failure.list
					continue
				fi

				# record chart to list file
				echo "${projName}/${durl}" >> dist/charts.list
				echo -e "${INFO} download chart: ${projName}/${durl} completed\n"
			done
		done
	done

	popd
}

main () {
	initialize_migrator
	BACKUP_DIR=$1
	prepare_backup_dir
	backup_harbor_data
}

main "$@"
