#!/bin/bash

# initialization
initialize_sync() {
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

# sync harbor images and charts
sync_harbor_images_charts() {
  harborUsername='xxx'
  harborPassword='xxx'
  srcHarborRegistry='src.harbor.com'
  dstHarborRegistry='dst.harbor.com'
  harborBasicAuthToken=$(echo -n "${harborUsername}:${harborPassword}" | base64)
  
  echo -e "${INFO} Start to login harbor..."
  docker login --username ${harborUsername} --password ${harborPassword} ${srcHarborRegistry}
  docker login --username ${harborUsername} --password ${harborPassword} ${dstHarborRegistry}
  
  echo -e "${INFO} Start to sync harbor images and charts..."
  # list projects
  projs=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${srcHarborRegistry}"'/api/projects?page=1&page_size=1000' | jq -r '.[] | "\(.project_id)=\(.name)"'`
  for proj in ${projs[*]}; do
    projId=`echo $proj|cut -d '=' -f 1`
    projName=`echo $proj|cut -d '=' -f 2`
    echo -e "${INFO} Start to sync images of project ${projName} ..."
   
    # create harbor project 
    curl -k -X POST -H "Authorization: Basic ${harborBasicAuthToken}" "https://${dstHarborRegistry}/api/projects" -H "accept: application/json" -H "Content-Type: application/json" -d '{ "project_name": "'"$projName"'", "metadata": { "public": "true" }}'  
  
    # list repos in one project
    repos=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${srcHarborRegistry}"'/api/repositories?page=1&page_size=100&project_id='"${projId}" | jq -r '.[] | "\(.id)=\(.name)"'`
    for repo in ${repos[*]}; do
      repoId=`echo $repo|cut -d '=' -f 1`
      repoName=`echo $repo|cut -d '=' -f 2`
      #echo ${projId} ${repoName};
  
      # list tags in one repo
      tags=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${srcHarborRegistry}"'/api/repositories/'"${repoName}"'/tags?detail=1' | jq -r '.[].name'`
      #echo ${tags[*]}
      for tag in ${tags[*]}; do
        # pull image
        docker pull ${srcHarborRegistry}/${repoName}:${tag}
        # tag image
        docker tag ${srcHarborRegistry}/${repoName}:${tag} ${dstHarborRegistry}/${repoName}:${tag}
        # push image 
        docker push ${dstHarborRegistry}/${repoName}:${tag}
      done
    done
    
    echo -e "${INFO} Start to sync charts of project ${projName} ..."
    # list charts in one project
    charts=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${srcHarborRegistry}"'/api/chartrepo/'"${projName}"'/charts' | jq -r '.[].name'`
    for chart in ${charts[*]}; do
      #echo ${chart}
  
      # list download urls in one chart
      durls=`curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" "https://${srcHarborRegistry}"'/api/chartrepo/'"${projName}"'/charts/'"${chart}" | jq -r '.[].urls[0]'`
      #echo ${durl[*]}
      for durl in ${durls[*]}; do
        #echo ${durl};
        echo -e "${INFO} Start to sync chart:${durl} of project ${projName} ..."
        # download chart
        curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" -o /tmp/chart.tgz "https://${srcHarborRegistry}/chartrepo/${projName}/${durl}"
        # upload chart
        curl -s -k -H "Authorization: Basic ${harborBasicAuthToken}" -X POST "https://${dstHarborRegistry}/api/chartrepo/${projName}/charts" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "chart=@/tmp/chart.tgz;type=application/gzip" 
      done
    done
    
  done
}

main() {
  initialize_sync
  sync_harbor_images_charts
}

main "$@"
