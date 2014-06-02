#!/bin/bash
# build the project and copy the files to the mapped folders
build_dir="../../build/"
build_pp_dir="${build_dir}/packetprocessor"
build_pp_bin="${build_pp_dir}/packet-processor-static"

www_root="mapped_folders/www/html/"
www_cgi="${www_root}/cgi-bin"
www_upload="${www_root}/upload"
www_service_src="../service/"
pcap_src_dir="../pcaps/"
cur_dir=$(pwd)

##################################
cd "$build_dir"
cmake ..
make

cd "$cur_dir"

echo "clean www-root..."
rm -rf "${www_root}"/

echo "copy packet processor to ${www_cgi}..."
mkdir -p "$www_cgi"
cp "${build_pp_bin}" "${www_cgi}/"

echo "copy web service to ${www_root}..."
cp -a "$www_service_src"/. ${www_root}

echo "copy sample pcaps to ${www_upload}..."
mkdir -p "$www_upload"
cp "${pcap_src_dir}"/* "$www_upload"

# ...add basic database setup here...
