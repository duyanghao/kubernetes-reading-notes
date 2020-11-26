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

initialize_migrator

echo -e "${INFO} Start to login harbor ..."

harborUsername='xxx'
harborPassword='xxx'
harborRegistry='domain.example.com'
harborBasicAuthToken=$(echo -n "${harborUsername}:${harborPassword}" | base64)

docker login --username ${harborUsername} --password ${harborPassword} ${harborRegistry}

# create directory
echo -e "$${INFO} Start to create directory: $1 ..."
mkdir $1
mkdir $1/images
mkdir $1/charts
# download images and charts
projs=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${harborRegistry}"'/api/projects?page=1&page_size=100&'"name=$1" | jq -r '.[] | "\(.project_id)=\(.name)"'`
for proj in ${projs[*]}; do
  projId=`echo $proj|cut -d '=' -f 1`
  projName=`echo $proj|cut -d '=' -f 2`
 
  echo -e "${INFO} Start to download image of $1 ..."
  # list repos in one project
  repos=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${harborRegistry}"'/api/repositories?page=1&page_size=100&project_id='"${projId}" | jq -r '.[] | "\(.id)=\(.name)"'`
  for repo in ${repos[*]}; do
    repoId=`echo $repo|cut -d '=' -f 1`
    repoName=`echo $repo|cut -d '=' -f 2`
    imageName=`echo $repoName|rev|cut -d '/' -f 1|rev`
    echo ${projId} ${repoName} ${imageName}

    # list tags in one repo
    tags=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${harborRegistry}"'/api/repositories/'"${repoName}"'/tags?detail=1' | jq -r '.[].name'`
    #echo ${tags[*]}
    for tag in ${tags[*]}; do
        #echo ${tag};
        # pull image
        docker pull ${harborRegistry}/${repoName}:${tag}
        docker save -o ${imageName}-${tag}.tar ${harborRegistry}/${repoName}:${tag}
        mv ${imageName}-${tag}.tar $1/images/${imageName}-${tag}.tar
    done
  done

  echo -e "${INFO} Start to download charts of $1 ..."
  # list charts in one project
  charts=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${harborRegistry}"'/api/chartrepo/'"${projName}"'/charts' | jq -r '.[].name'`
  for chart in ${charts[*]}; do
    #echo ${chart}
    # list download urls in one chart
    durls=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${harborRegistry}"'/api/chartrepo/'"${projName}"'/charts/'"${chart}" | jq -r '.[].urls[0]'`
    #echo ${durl[*]}
    for durl in ${durls[*]}; do
        #echo ${durl};
        chartName=`echo ${durl}|cut -d/ -f 2`
        # download chart
        curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" -o ${chartName} "https://${harborRegistry}/chartrepo/${projName}/${durl}"
        mv ${chartName} $1/charts/
    done
  done
  
done

#archive project
echo -e "$${INFO} Start to archive project: $1 ..."
tar -czf $1.tgz $1
