package astdata

import (
	"encoding/json"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/gobeam/stringy"
	"io/ioutil"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackage(t *testing.T) {
	p, err := ParsePackage("fixture")
	require.NoError(t, err)
	assert.Equal(t, p.Path(), "fixture")
	assert.Equal(t, p.Name(), "fixture")

	_, err = translateToFullPath("invalid_path")
	assert.Error(t, err)
	_, err = translateToFullPath("not/exists/package")
	assert.Error(t, err)

	p = &Package{}

	f1, err := ParseFile(testArrr, p)
	require.NoError(t, err)
	f2, err := ParseFile(testFunc, p)
	require.NoError(t, err)
	f3, err := ParseFile(testImport, p)
	require.NoError(t, err)
	f4, err := ParseFile(testConst, p)
	require.NoError(t, err)

	p.files = append(p.files, f1, f2, f3, f4)

	assert.Len(t, p.Files(), 4)
	assert.NotEmpty(t, p.Functions())
	assert.NotEmpty(t, p.Variables())
	assert.NotEmpty(t, p.Types())
	assert.NotEmpty(t, p.Imports())
	assert.NotEmpty(t, p.Constants())
}

type CodeGenConf struct {
	genTplFile              bool
	genProxyWMSBasicAPICode bool
	genWMSBasicV2APICode    bool
	genSrcProxyCodeFile     bool
	name                    string
	srcBase                 string
	pbBase                  string
	pbSrcBase               string
	basicV2APICodeBase      string
	basicV2APIPkg           string
	basicV2ViewType         string
	codeBase                string
	proxyStructType         string
	callMngMap              map[string]string
	targetStruct            string
	targetStructs           []string
}

func TestBasicPkgs(t *testing.T) {
	packageMap := map[string]*Package{}
	pkgs := []string{
		//view
		"apps/basic/view/vsku",
		"apps/config/view/vsizetype",
		"apps/config/view/vlifecyclerule",
		"apps/config/view/vhighvalue",

		//manager
		"apps/config/manager/msizetype",
		"apps/basic/manager/msku",
		"apps/config/manager/mhighvalue",
		"apps/config/manager/mlifecyclerule",

		//repo
		"apps/basic/service/ssku",
		"apps/basic/service/ssku/sskuexport",
	}

	for _, pkg := range pkgs {
		err := ParsePackage2(packageMap, pkg, true)
		if err != nil {
			t.Error(err.Error())
		}
	}

	importPkgs := []string{}
	for _, pkg := range pkgs {
		pkgObj := packageMap[pkg]
		if pkgObj != nil {
			println(fmt.Sprintf("pkg %v ok ", pkgObj.Name()))
		}
		for _, i := range pkgObj.Imports() {
			pkgName := i.Path()
			if strings.Contains(pkgName, "wms-v2") {
				importPkgs = append(importPkgs, pkgName)
			}
		}
	}

	println(ToPrettyJSON(uniqSlice(importPkgs...)))

	println("done")

}

func TestWMSV2(t *testing.T) {
	packageMap := map[string]*Package{}
	//genConf := getMsizeConf()
	//genConf := getMHighbvalueConf()
	genConf := getMSKUConf()
	//genConf.genTplFile = true
	genConf.genProxyWMSBasicAPICode = true
	//genConf.genWMSBasicV2APICode = true
	//genConf.genSrcProxyCodeFile = true
	err := ParsePackage2(packageMap, genConf.name, true)
	if err != nil {
		t.Error(err.Error())
	}
	p := packageMap[genConf.name]
	pcode := parsePCode(p, packageMap, genConf)
	pcode.conf = genConf
	pcode.pkgMap = packageMap

	err = parsePbStructs(genConf.pbSrcBase, pcode, packageMap)
	if err != nil {
		t.Error(err.Error())
	}

	//tpl
	if genConf.genTplFile {
		err = genProxyAPIPbTpl(genConf.pbBase, pcode, packageMap)
		if err != nil {
			t.Error(err.Error())
		}
		extLines := []string{`message MapItem{
  optional string m_key = 1;
  optional string m_value = 2;
  optional string m_type = 3;
}
message PageInItem{
  optional  int64  Pageno = 1;       //页码
  optional  int64     count = 2 ;    // 数量
  optional  string  order_by = 3;    // 为空字符串 代表不需要排序
  optional  bool  is_get_total = 4;  // 为False代表不需要获取总数
}
message MapStrsItem{
  optional string m_key = 1;
  repeated string m_vals = 2;
}
message MapIntsItem{
  optional string m_key = 1;
  repeated int64 m_vals = 2;
}
message MapUint64Item{
  optional uint64 m_key = 1;
  optional int64 m_val = 2;
}
message MapSKUTagsItem{
  optional string sku_id = 1;
  repeated  SKUTagEntityItem tags = 2;
}
message MapIntStrsItem{
  optional int64 m_key = 1;
  repeated string m_vals = 2;
}
message ExportShopRequestItem{
  optional int64 shop_id= 1;
  optional int64 cb_option = 2;
  optional int64 is_sn_mgt = 3;
  optional int64 status = 4;
}
message MapCategoryWhsAttrItem{
  optional int64  id = 1;
  optional CategoryWhsAttrItem  attr = 2;
}
message MapCategoryZonePathwayConfList{
  optional int64  id = 1;
  repeated CategoryZonePathwayConfItem  list = 2;
}
message MapCategoryTreeItemList{
  optional int64  id = 1;
  repeated CategoryTreeItem  list = 2;
}
message MapCategoryTreeItem{
  optional int64  id = 1;
  optional CategoryTreeItem  item = 2;
}
message MapSkuProdExpiryDateFormatTabItem{
  optional string  sku_id = 1;
  optional SkuProdExpiryDateFormatTabItem  item = 2;
}
`}
		if genConf.name == "apps/basic/manager/msku" {
			extLines = append(extLines, "message Option {\n  optional bool use_master = 1;\n}")
		}

		pcode.ouStructTplDbsMaps["entity"] = append(pcode.ouStructTplDbsMaps["entity"], extLines...)

		err = genTplFile(genConf.pbBase, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}

	if genConf.genProxyWMSBasicAPICode {
		//wmsbasic api
		err = genProxyAPICodeFile(genConf, packageMap, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}

	if genConf.genWMSBasicV2APICode {
		//wmsbasicv2 api
		pbPkg := packageMap[genConf.pbSrcBase]
		err = genBasicV2APICodeFile(genConf.basicV2APIPkg, genConf.basicV2ViewType, genConf.basicV2APICodeBase, pbPkg, pcode, packageMap)
		if err != nil {
			t.Error(err.Error())
		}
	}

	if genConf.genSrcProxyCodeFile {
		err = genSrcProxyCodeFile(genConf, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}
	//genWMSV2ProxyPB(p)
	//genWMSV2ProxyAPI(p)
	//genWMSV2ProxyTestAPI(p)
	//genBasicAPI(p)

}

func getMsizeConf() *CodeGenConf {
	var genConf = &CodeGenConf{
		genTplFile:              false,
		genProxyWMSBasicAPICode: false,
		genWMSBasicV2APICode:    true,
		genSrcProxyCodeFile:     false,
		name:                    "apps/config/manager/msizetype",
		srcBase:                 "/Users/yunfeizhu/Code/golang/wms-v2/apps/config/manager/msizetype",
		codeBase:                "/Users/yunfeizhu/Code/golang/wms-v2/apps/wmslib/wmsbasic",
		pbBase:                  "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2",
		pbSrcBase:               "apps/basic/pbbasicv2/pbmsizetype",
		basicV2APICodeBase:      "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2/apps/config/view/vsizetype",
		basicV2APIPkg:           "vsizetype",
		basicV2ViewType:         "SizeTypeView",
	}
	return genConf
}

func getMHighbvalueConf() *CodeGenConf {
	callMngMap := map[string]string{
		"HighValueManager": "highValueManager",
		//"TaskSizeTypeManager": "tasksizeTypeManger",
	}
	var genConf = &CodeGenConf{
		genTplFile:              false,
		genProxyWMSBasicAPICode: false,
		genWMSBasicV2APICode:    false,
		genSrcProxyCodeFile:     false,
		name:                    "apps/config/manager/mhighvalue",
		srcBase:                 "/Users/yunfeizhu/Code/golang/wms-v2/apps/config/manager/mhighvalue",
		codeBase:                "/Users/yunfeizhu/Code/golang/wms-v2/apps/wmslib/wmsbasic",
		pbBase:                  "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2",
		pbSrcBase:               "apps/basic/pbbasicv2/pbmhighvalue",
		basicV2APICodeBase:      "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2/apps/config/view/vhighvalue",
		basicV2APIPkg:           "vhighvalue",
		basicV2ViewType:         "HighValueConfigView",
		proxyStructType:         "HighValueManager",
		callMngMap:              callMngMap,
	}
	return genConf
}

func getMSKUConf() *CodeGenConf {
	callMngMap := map[string]string{
		"SKUManager": "skuManager",
		//"TaskSizeTypeManager": "tasksizeTypeManger",
	}
	var genConf = &CodeGenConf{
		genTplFile:              false,
		genProxyWMSBasicAPICode: false,
		genWMSBasicV2APICode:    false,
		genSrcProxyCodeFile:     false,
		name:                    "apps/basic/manager/msku",
		srcBase:                 "/Users/yunfeizhu/Code/golang/wms-v2/apps/basic/manager/msku",
		codeBase:                "/Users/yunfeizhu/Code/golang/wms-v2/apps/wmslib/wmsbasic",
		pbBase:                  "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2",
		pbSrcBase:               "apps/basic/pbbasicv2/pbmsku",
		basicV2APICodeBase:      "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2/apps/basic/view/vsku",
		basicV2APIPkg:           "vsku",
		basicV2ViewType:         "SKUView",
		proxyStructType:         "SKUManager",
		targetStructs:           []string{"SKUManager"},
		targetStruct:            "SKUManager",
		callMngMap:              callMngMap,
	}
	return genConf
}
func getMlifecycleConf() *CodeGenConf {
	callMngMap := map[string]string{
		"LifeCycleRuleManager": "lifeCycleRuleConfigMng",
		//"TaskSizeTypeManager": "tasksizeTypeManger",
	}
	var genConf = &CodeGenConf{
		genTplFile:              false,
		genProxyWMSBasicAPICode: false,
		genWMSBasicV2APICode:    false,
		genSrcProxyCodeFile:     false,
		name:                    "apps/config/manager/mlifecyclerule",
		srcBase:                 "/Users/yunfeizhu/Code/golang/wms-v2/apps/config/manager/mlifecyclerule",
		codeBase:                "/Users/yunfeizhu/Code/golang/wms-v2/apps/wmslib/wmsbasic",
		pbBase:                  "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2",
		pbSrcBase:               "apps/basic/pbbasicv2/pbmlifecyclerule",
		//wmsv2-basic-v2
		targetStruct:  "LifeCycleRuleManager",
		targetStructs: []string{"LifeCycleRuleManager"},

		basicV2APICodeBase: "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2/apps/config/view/vlifecyclerule",
		basicV2APIPkg:      "vlifecyclerule",
		basicV2ViewType:    "LifeCycleRuleConfigView",
		proxyStructType:    "lifeCycleRuleConfigMng",
		callMngMap:         callMngMap,
	}
	return genConf
}

func parsePbStructs(pbSrcBase string, pcode *PCode, packageMap map[string]*Package) error {

	//module := pcode.p.name
	//pkgPbDir := "pb" + module
	////tpl := base + "/" + pkgPbDir
	////tplCommon := base + "/pbcommon"
	//pkgBase := "git.garena.com/shopee/bg-logistics/tianlu/wms-protobuf/apps/basic/pbbasicv2"
	//importPkgBase := "apps/basic/pbbasicv2"
	//goPkgPath := fmt.Sprintf("%s/%s", pkgBase, pkgPbDir)
	//importDtoPkg := fmt.Sprintf("%s/%s/%s_dto.tpl.proto", importPkgBase, pkgPbDir, module)
	//importCommonPkg := fmt.Sprintf("%s/%s/entity_entity.tpl.proto", importPkgBase, pkgPbDir)

	err := ParsePbPackage2(packageMap, pbSrcBase)
	if err != nil {
		return err
	}
	return nil
}

func genProxyAPICodeFile(genConf *CodeGenConf, packageMap map[string]*Package, pcode *PCode) error {
	base := genConf.codeBase
	pbsrcBase := genConf.pbSrcBase
	module := pcode.p.name
	filePre := base + "/" + module
	pbSrcPkg := packageMap[pbsrcBase]
	var err error

	packageHead := "package wmsbasic"
	apiFiles := []string{packageHead}

	apiFiles = append(apiFiles, buildPackageProxyBasicAPI(pcode)...)
	err = ioutil.WriteFile(filePre+"_basic_api.go", []byte(strings.Join(apiFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	dtoFiles := []string{packageHead}
	dtoFiles = append(dtoFiles, pcode.proxySrcPkgAPIStructs...)
	if module == "msku" {
		dtoFiles = append(dtoFiles, "type ExportShopRequestItem struct {\n\tShopID   int64 `json:\"shop_id\"`\n\tCbOption int64 `json:\"cb_option\"`\n\tIsSnMgt  int64 `json:\"is_sn_mgt\"`\n\tStatus   int64 `json:\"status\"`\n}\n")
	}
	err = ioutil.WriteFile(filePre+"_basic_dto.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	pkgName := module
	receiverPrex := fmt.Sprintf("func (m *%sBasicAPI)", upFirstChar(pkgName))
	var basicAPIProxyBodys string
	for _, basicapi := range pcode.basicAPIPbsMap {
		paramSignStr := basicapi.api.methodReqSign()
		returnSign := basicapi.api.methodReturnSign()
		head := fmt.Sprintf("%s%s (%s)%s {", receiverPrex, basicapi.api.Method, paramSignStr, returnSign)
		body := basicapi.api.proxyBasicFuncBodyWithConveted(pbSrcPkg, packageMap)

		basicAPIProxyBodys += head + "\n" + body
		println(head, "\n", body)

	}

	dtoFiles = []string{"package wmsbasic", pcode.genProxyAPIStructDefAndConstruct(), basicAPIProxyBodys}
	err = ioutil.WriteFile(filePre+"_basic_api_impl.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	var helpers []string
	for _, basicapi := range pcode.basicAPIPbsMap {

		api := basicapi.api
		//head := fmt.Sprintf("func to%sPbReq(%s)(*%s,*wmserror.WMSError) {", api.Method, api.methodReqAliasWithoutCtx(true), basicapi.api.apiPbReqType())
		//head = api.convertToPbReqSign()
		body := api.proxyBasicConvertReqBody(pbSrcPkg, packageMap)
		//curBody := head + "\n" + body + "\n}"
		helpers = append(helpers, body)

		//head = fmt.Sprintf("func parse%sPbResp(resp *%s) %s{", api.Method, api.apiPbRespType(), basicapi.api.methodReturnSign())
		if api.isNeedViewConvertResp() {
			body = api.proxyBasicConvertRespBody(pbSrcPkg, packageMap)
			helpers = append(helpers, body)
		}
	}

	dtoFiles = []string{"package wmsbasic", strings.Join(helpers, "\n")}
	err = ioutil.WriteFile(filePre+"_basic_dto_converter.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	dtoFiles = []string{"package " + genConf.basicV2APIPkg, strings.Join(helpers, "\n")}
	helperPref := fStr("%s/%s", genConf.basicV2APICodeBase, module)
	err = ioutil.WriteFile(helperPref+"_dto_converter.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	var endpoints = []string{}
	endpoints = append(endpoints, fmt.Sprintf("// %s endpoint", module))
	endpoints = append(endpoints, "var (")
	for _, api := range pcode.basicAPIPbsMap {
		endpoints = append(endpoints, fmt.Sprintf("%s WmsBasicApi = \"%s\"", api.api.endpointEnum(), api.Path))
	}
	endpoints = append(endpoints, ")")

	dtoFiles = []string{"package wmsbasic"}
	dtoFiles = append(dtoFiles, endpoints...)
	err = ioutil.WriteFile(filePre+"_basic_endpoint.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}
	return nil
}

func genBasicV2APICodeFile(pkgName string, basicV2ViewType string, base string, pbSrcPkg *Package, pcode *PCode, packageMap map[string]*Package) error {
	callMngMap := pcode.conf.callMngMap
	module := pcode.p.name
	var err error
	filePre := base + "/" + module

	packageHead := fmt.Sprintf("package %s", pkgName)
	apiFiles := []string{packageHead}

	apis, sortedAPIList := genRouterInit(module, pcode)

	apiFiles = append(apiFiles, apis...)

	err = ioutil.WriteFile(filePre+"_proxy_handler.go", []byte(strings.Join(apiFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	basicAPIImps := genViewHandlersV2(packageHead, sortedAPIList, callMngMap, basicV2ViewType, pbSrcPkg, packageMap, module)

	err = ioutil.WriteFile(filePre+"_proxy_handler_impl.go", []byte(strings.Join(basicAPIImps, "\n")), 0644)
	if err != nil {
		return err
	}
	converter := genViewHandlersV2ConvertReq(packageHead, sortedAPIList, callMngMap, basicV2ViewType, pbSrcPkg, packageMap, module)

	err = ioutil.WriteFile(filePre+"_proxy_handler_req_converter.go", []byte(strings.Join(converter, "\n")), 0644)
	if err != nil {
		return err
	}
	respConverter := genViewHandlersV2ConvertResp(packageHead, sortedAPIList, callMngMap, basicV2ViewType, pbSrcPkg, packageMap, module)

	err = ioutil.WriteFile(filePre+"_proxy_handler_resp_converter.go", []byte(strings.Join(respConverter, "\n")), 0644)
	if err != nil {
		return err
	}

	return nil
}

func genViewHandlers(packageHead string, sortedAPIList []*BASICAPI, callMngMap map[string]string, basicV2ViewType string, pbSrcPkg *Package, packageMap map[string]*Package, module string) []string {
	basicAPIImps := []string{
		packageHead,
	}
	for _, basicapi := range sortedAPIList {
		receiver := basicapi.api.ReceiverName
		curReceiver := callMngMap[receiver]
		if strings.Contains(receiver, "Proxy") {
			continue
		}
		funcs := []string{}
		viewMethod := basicapi.api.endpointEnum()
		sign := fmt.Sprintf("func (v *%s) %s(ctx context.Context, header *wrapper.ReqHeader, request interface{}) (interface{}, *wmserror.WMSError) {", basicV2ViewType, viewMethod)
		funcs = append(funcs, sign)

		//大于的请求，才需要解析req
		if len(basicapi.ReqFields) > 1 {
			funcs = append(funcs, fmt.Sprintf("req := request.(*%s)", basicapi.api.apiPbReqType()))
		}
		paramLines := []string{}

		paramLines = append(paramLines, "")
		funcs = append(funcs, paramLines...)

		_, lines := basicapi.api.genBasicToWMSV2PreItemDefLines(pbSrcPkg, packageMap)
		funcs = append(funcs, lines...)

		method := basicapi.api.Method
		invokeParamStr := strings.Join(basicapi.viewInvokeAlias(), ",")
		invokeRetStr := strings.Join(basicapi.api.apiRets(), ",")

		callLine := fmt.Sprintf(" %s:= v.%s.%s(%s)", invokeRetStr, curReceiver, method, invokeParamStr)
		if len(basicapi.api.apiPbRets()) == 1 && basicapi.api.genBasicV2Err {
			callLine = strings.ReplaceAll(callLine, ":", "")
		}
		handlerErr := basicapi.viewHandlerErr()
		funcs = append(funcs, callLine)
		funcs = append(funcs, handlerErr)

		//convert to
		//convert
		for i, retType := range basicapi.api.Resp {
			if retType == "*wmserror.WMSError" {
				continue
			}
			if isNormalType(retType) {
				continue
			}
			originRet := fmt.Sprintf("ret%v", i+1)
			val := originRet
			var def string
			pbType := toPbType(retType, nil)
			if strings.Contains(retType, "[]") {
				val += "Items"
				def = fmt.Sprintf("%v:=[]*pb%s.%s{}", val, module, pbType)
			} else {
				val += "Item"
				def = fmt.Sprintf("%v:=&pb%s.%s{}", val, module, pbType)
			}
			funcs = append(funcs, def)
			copyJson := `		if jsErr := copier.Copy(%s,%s); jsErr != nil {
			return nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())
		}`
			if strings.Contains(def, "[]") {
				funcs = append(funcs, fmt.Sprintf(copyJson, originRet, "&"+val))
			} else {
				funcs = append(funcs, fmt.Sprintf(copyJson, originRet, "&"+val))
			}
		}

		if len(basicapi.api.Resp) == 1 {
			funcs = append(funcs, fmt.Sprintf("resp := &%s{}", basicapi.api.apiPbRespType()))
		} else {
			funcs = append(funcs, fmt.Sprintf("resp := &%s{", basicapi.api.apiPbRespType()))
			for i, retType := range basicapi.api.Resp {
				if retType == "*wmserror.WMSError" {
					continue
				}
				val := fmt.Sprintf("ret%v", i+1)
				funcs = append(funcs, fmt.Sprintf("Ret%v:%s,", i+1, convertToPbType(retType, val)))
			}
			funcs = append(funcs, "}")
		}
		funcs = append(funcs, "return resp,nil")
		funcs = append(funcs, "}")

		basicAPIImps = append(basicAPIImps, funcs...)
	}
	return basicAPIImps
}

var fStr = fmt.Sprintf

func genViewHandlersV2(packageHead string, sortedAPIList []*BASICAPI, callMngMap map[string]string, basicV2ViewType string, pbSrcPkg *Package, packageMap map[string]*Package, module string) []string {
	basicAPIImps := []string{
		packageHead,
	}
	for _, basicapi := range sortedAPIList {
		api := basicapi.api
		receiver := basicapi.api.ReceiverName
		curReceiver := callMngMap[receiver]
		if strings.Contains(receiver, "Proxy") {
			continue
		}
		funcs := []string{}
		viewMethod := basicapi.api.endpointEnum()
		sign := fmt.Sprintf("func (v *%s) %s(ctx context.Context, header *wrapper.ReqHeader, request interface{}) (interface{}, *wmserror.WMSError) {", basicV2ViewType, viewMethod)
		funcs = append(funcs, sign)

		//大于的请求，才需要解析req
		if len(basicapi.ReqFields) > 1 {
			funcs = append(funcs, fmt.Sprintf("req := request.(*%s)", basicapi.api.apiPbReqType()))
		}

		method := basicapi.api.Method
		invokeParamStr := strings.Join(basicapi.viewInvokeAliasWithoutCtx(), ",")
		invokeRetStr := strings.Join(basicapi.api.apiRets(), ",")

		parseLines := []string{}
		//convert to original param
		parseReqMethod := api.parseReqToOriginMethod()
		if len(api.ReqFields) > 1 {
			parseLines = append(parseLines, fStr("%s,ctErr :=%s(req)", invokeParamStr, parseReqMethod))
			parseLines = append(parseLines, "\tif ctErr != nil {\n\t\treturn nil, ctErr.Mark()\n\t}")
		}
		funcs = append(funcs, parseLines...)

		callLine := fmt.Sprintf(" %s:= v.%s.%s(ctx,%s)", invokeRetStr, curReceiver, method, invokeParamStr)
		if len(basicapi.api.apiPbRets()) == 1 && basicapi.api.genBasicV2Err {
			callLine = strings.ReplaceAll(callLine, ":", "")
		}
		handlerErr := basicapi.viewHandlerErr()
		funcs = append(funcs, callLine)
		funcs = append(funcs, handlerErr)

		//convert to pb resp
		toPbRespSignMethod := api.helperConvertToPbRespSignMethod()
		if api.isNeedViewConvertResp() {
			funcs = append(funcs, fStr("return %s(%s)", toPbRespSignMethod, api.methodRespAliasWithoutErr(false)))
		} else {
			funcs = append(funcs, fStr("return &%s{},nil", api.apiPbRespType()))
		}
		funcs = append(funcs, "}")
		basicAPIImps = append(basicAPIImps, funcs...)
		continue

		//convert to
		//convert
		for i, retType := range basicapi.api.Resp {
			if retType == "*wmserror.WMSError" {
				continue
			}
			if isNormalType(retType) {
				continue
			}
			originRet := fmt.Sprintf("ret%v", i+1)
			val := originRet
			var def string
			pbType := toPbType(retType, nil)
			if strings.Contains(retType, "[]") {
				val += "Items"
				def = fmt.Sprintf("%v:=[]*pb%s.%s{}", val, module, pbType)
			} else {
				val += "Item"
				def = fmt.Sprintf("%v:=&pb%s.%s{}", val, module, pbType)
			}
			funcs = append(funcs, def)
			copyJson := `		if jsErr := copier.Copy(%s,%s); jsErr != nil {
			return nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())
		}`
			if strings.Contains(def, "[]") {
				funcs = append(funcs, fmt.Sprintf(copyJson, originRet, "&"+val))
			} else {
				funcs = append(funcs, fmt.Sprintf(copyJson, originRet, "&"+val))
			}
		}

		if len(basicapi.api.Resp) == 1 {
			funcs = append(funcs, fmt.Sprintf("resp := &%s{}", basicapi.api.apiPbRespType()))
		} else {
			funcs = append(funcs, fmt.Sprintf("resp := &%s{", basicapi.api.apiPbRespType()))
			for i, retType := range basicapi.api.Resp {
				if retType == "*wmserror.WMSError" {
					continue
				}
				originRet := fmt.Sprintf("ret%v", i+1)
				val := originRet
				////var def string
				//if strings.Contains(retType, "[]") {
				//	val += "Items"
				//} else if !isNormalType(retType) {
				//	val += "Item"
				//}
				funcs = append(funcs, fmt.Sprintf("Ret%v:%s,", i+1, convertToPbType(retType, val)))
			}
			funcs = append(funcs, "}")
		}
		funcs = append(funcs, "return resp,nil")
		funcs = append(funcs, "}")

		basicAPIImps = append(basicAPIImps, funcs...)
	}
	return basicAPIImps
}

func genViewHandlersV2ConvertReq(packageHead string, sortedAPIList []*BASICAPI, callMngMap map[string]string, basicV2ViewType string, pbSrcPkg *Package, packageMap map[string]*Package, module string) []string {
	basicAPIImps := []string{
		packageHead,
	}
	for _, basicapi := range sortedAPIList {
		api := basicapi.api
		receiver := basicapi.api.ReceiverName
		if strings.Contains(receiver, "Proxy") {
			continue
		}
		if !api.isNeedViewConvertReq() {
			continue
		}

		if itemMap, ok := parseReqItemsCodeMap[api.Module()]; ok {
			code := itemMap[api.parseReqToOriginMethod()]
			if len(code) > 0 {
				basicAPIImps = append(basicAPIImps, code)
				continue
			}
		}

		funcs := []string{}
		funcs = append(funcs, api.parseReqToOriginMethodSign())

		_, lines := api.genBasicToWMSV2PreItemDefLines(pbSrcPkg, packageMap)
		funcs = append(funcs, lines...)
		//funcs = append(funcs, "panic(1)")
		funcs = append(funcs, fmt.Sprintf("return %s,nil", strings.Join(api.apiReqAliasWithoutCtx(), ",")))

		funcs = append(funcs, "}")

		basicAPIImps = append(basicAPIImps, funcs...)
	}
	return basicAPIImps
}

func genViewHandlersV2ConvertResp(packageHead string, sortedAPIList []*BASICAPI, callMngMap map[string]string, basicV2ViewType string, pbSrcPkg *Package, packageMap map[string]*Package, module string) []string {
	basicAPIImps := []string{
		packageHead,
	}
	for _, basicapi := range sortedAPIList {
		api := basicapi.api
		receiver := basicapi.api.ReceiverName
		if strings.Contains(receiver, "Proxy") {
			continue
		}
		if !api.isNeedViewConvertResp() {
			continue
		}

		if itemMap, ok := parseReqItemsCodeMap[api.Module()]; ok {
			code := itemMap[api.helperConvertToPbRespSignMethod()]
			if len(code) > 0 {
				basicAPIImps = append(basicAPIImps, code)
				continue
			}
		}

		funcs := []string{}
		funcs = append(funcs, api.helperConvertToPbRespSign())

		//convert
		for i, retType := range basicapi.api.Resp {
			if retType == "*wmserror.WMSError" {
				continue
			}
			if isNormalType(retType) {
				continue
			}
			originRet := fmt.Sprintf("ret%v", i+1)
			val := originRet
			var def string
			pbType := toPbType(retType, nil)
			if strings.Contains(retType, "[]") {
				val += "Items"
				def = fmt.Sprintf("%v:=[]*pb%s.%s{}", val, module, pbType)
			} else {
				val += "Item"
				def = fmt.Sprintf("%v:=&pb%s.%s{}", val, module, pbType)
			}
			funcs = append(funcs, def)
			copyJson := `		if jsErr := copier.Copy(%s,%s); jsErr != nil {
			return nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())
		}`
			if strings.Contains(def, "[]") {
				funcs = append(funcs, fmt.Sprintf(copyJson, originRet, "&"+val))
			} else {
				funcs = append(funcs, fmt.Sprintf(copyJson, originRet, "&"+val))
			}
		}

		if len(basicapi.api.Resp) == 1 {
			funcs = append(funcs, fmt.Sprintf("resp := &%s{}", basicapi.api.apiPbRespType()))
		} else {
			funcs = append(funcs, fmt.Sprintf("resp := &%s{", basicapi.api.apiPbRespType()))
			for i, retType := range basicapi.api.Resp {
				if retType == "*wmserror.WMSError" {
					continue
				}
				val := fmt.Sprintf("ret%v", i+1)
				funcs = append(funcs, fmt.Sprintf("Ret%v:%s,", i+1, convertToPbType(retType, val)))
			}
			funcs = append(funcs, "}")
		}
		funcs = append(funcs, "return resp,nil")
		funcs = append(funcs, "}")

		basicAPIImps = append(basicAPIImps, funcs...)
	}
	return basicAPIImps
}

func genRouterInit(module string, pcode *PCode) ([]string, []*BASICAPI) {
	var apis []string
	apis = append(apis, fmt.Sprintf("func init%sProxyHandler(router *wrapper.BasicRouterWrapper, view *%s){", upFirstChar(module), pcode.conf.basicV2ViewType))

	sortedAPIList := []*BASICAPI{}
	for _, basicapi := range pcode.basicAPIPbsMap {
		sortedAPIList = append(sortedAPIList, basicapi)
	}
	sort.Slice(sortedAPIList, func(i, j int) bool {
		return sortedAPIList[i].api.Method < sortedAPIList[j].api.Method
	})
	for _, basicapi := range sortedAPIList {

		routerMethod := basicapi.ProxyOpenapiMethod()
		apiPath := basicapi.Path
		viewMethod := basicapi.api.endpointEnum()
		pbReq := basicapi.api.apiPbReqType()

		handler := fmt.Sprintf("router.%s(\"%s\", view.%s, &%s{})", routerMethod, apiPath, viewMethod, pbReq)
		apis = append(apis, handler)
	}
	apis = append(apis, "}")
	return apis, sortedAPIList
}

type ItemType string

func (i ItemType) IsInnerStruct() bool {
	itemTypeStr := string(i)
	return !strings.Contains(itemTypeStr, ".") &&
		!strings.EqualFold(itemTypeStr, "string") &&
		!strings.EqualFold(itemTypeStr, "int64") &&
		!strings.EqualFold(itemTypeStr, "int") &&
		!strings.Contains(itemTypeStr, "map[string]")
}

func (i ItemType) IsOuterStruct() bool {
	itemTypeStr := string(i)
	return strings.Contains(itemTypeStr, ".")
}

func (i ItemType) String() string {
	return string(i)
}
func genProxyAPIPbTpl(base string, pcode *PCode, packageMap map[string]*Package) error {
	module := pcode.p.name
	pkgPbDir := "pb" + module
	//tpl := base + "/" + pkgPbDir
	//tplCommon := base + "/pbcommon"
	//pbBase := "/Users/yunfeizhu/Code/golang/wms-protobuf/apps/basic/pbbasicv2"
	pkgBase := "git.garena.com/shopee/bg-logistics/tianlu/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2"
	importPkgBase := "apps/basic/pbbasicv2"
	goPkgPath := fmt.Sprintf("%s/%s", pkgBase, pkgPbDir)
	importDtoPkg := fmt.Sprintf("%s/%s/%s_dto.tpl.proto", importPkgBase, pkgPbDir, module)
	importCommonPkg := fmt.Sprintf("%s/%s/entity_entity.tpl.proto", importPkgBase, pkgPbDir)

	//
	//tplHead := "syntax = \"proto2\";"
	//innerCommonStructs := []string{}
	//for _, pb := range pcode.basicAPIPbs {
	//	inStructs := pb.api.genInnerDefPkgStructs()
	//	innerCommonStructs = append(innerCommonStructs, inStructs...)
	//}

	var pTpls []string
	pTpls = append(pTpls, "syntax = \"proto2\";")
	pTpls = append(pTpls, fmt.Sprintf("option go_package = \"%s\";", goPkgPath))
	pTpls = append(pTpls, fmt.Sprintf("package %s;", pkgPbDir))
	pTpls = append(pTpls, fmt.Sprintf("import \"%s\";", importDtoPkg))
	pTpls = append(pTpls, fmt.Sprintf("import \"%s\";", importCommonPkg))
	pTpls = append(pTpls, "")
	pTpls = append(pTpls, "")

	apiPbLinesMap := map[string][]string{}
	for _, pb := range pcode.basicAPIPbs {
		//println("path: ", pb.Path)
		//println("method: ", pb.Method)
		_, ok := apiPbLinesMap[pb.Path]
		if ok {
			continue
		}

		pTpls = append(pTpls, "// "+pb.api.genBasicAPIMethod())
		tplsLines := genAPIPbTpls(pb, packageMap)
		pTpls = append(pTpls, tplsLines...)

		apiPbLinesMap[pb.Path] = append(apiPbLinesMap[pb.Path], tplsLines...)

		//println(ToPrettyJSON(tplsLines))
		//println("")
		//println("")
	}

	pcode.apiPbLinesMap = apiPbLinesMap
	pcode.allPbLines = pTpls

	inItemStrs, inItemTagsMap := parseInnerStruct(pcode.innerStructTypes, pcode, packageMap)

	inStructTplDbs := genTplByJsonTagsMap(inItemTagsMap)
	inStructTagTypes := getStructTypeSet(inItemTagsMap)
	pcode.inItemTagsMap = inItemTagsMap

	println("all in item types:\n", ToPrettyJSON(inItemStrs))
	println("all in item types map:\n", ToPrettyJSON(inItemTagsMap))
	println(strings.Join(inStructTplDbs, "\n"))
	println("in struct tyeps:\n  ", ToPrettyJSON(inStructTagTypes))

	var innerTpls []string
	innerTpls = append(innerTpls, "syntax = \"proto2\";")
	innerTpls = append(innerTpls, fmt.Sprintf("option go_package = \"%s\";", goPkgPath))
	innerTpls = append(innerTpls, fmt.Sprintf("package %s;", pkgPbDir))
	if module == "msku" {
		message := fmt.Sprintf("%s/%s/message_entity.tpl.proto", importPkgBase, pkgPbDir)
		innerTpls = append(innerTpls, fmt.Sprintf("import \"%s\";", message))
	}
	innerTpls = append(innerTpls, fmt.Sprintf("import \"%s\";", importCommonPkg))
	innerTpls = append(innerTpls, "")
	innerTpls = append(innerTpls, "")
	innerTpls = append(innerTpls, "")

	innerTpls = append(innerTpls, inStructTplDbs...)

	pcode.innerStructsPbTpls = innerTpls

	//apiCommonStr := strings.Join(innerTpls, "\n")
	//err = ioutil.WriteFile(fmt.Sprintf("%s/%s_dto.tpl.proto", tpl, module), []byte(apiCommonStr), 0644)
	//if err != nil {
	//	println(err.Error())
	//}

	//
	println("out struct types:\n", ToPrettyJSON(pcode.outStructList))
	outItemStrs, ouItemTagsMap := parseOuterStruct(pcode.outStructList, pcode, packageMap)
	println("out struct types str:\n", ToPrettyJSON(outItemStrs))
	println("out struct types json tags:\n", ToPrettyJSON(ouItemTagsMap))
	ouStructTplDbsMaps := genOuterTplByJsonTagsMap(ouItemTagsMap)
	println("out struct types json tags:\n", ToPrettyJSON(ouItemTagsMap))
	//println(strings.Join(ouStructTplDbs, "\n"))

	var outerCommonTpls []string
	outerCommonTpls = append(outerCommonTpls, "syntax = \"proto2\";")
	outerCommonTpls = append(outerCommonTpls, fmt.Sprintf("option go_package = \"git.garena.com/shopee/bg-logistics/tianlu/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2/%s\";", pkgPbDir))
	outerCommonTpls = append(outerCommonTpls, fmt.Sprintf("package %s;", pkgPbDir))
	outPkgPbLinesMap := map[string][]string{}
	for pName, items := range ouStructTplDbsMaps {
		var outerTpls []string
		outerTpls = append(outerTpls, outerCommonTpls...)
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, items...)

		outPkgPbLinesMap[pName] = outerTpls
	}
	if len(outPkgPbLinesMap["entity"]) == 0 {
		outPkgPbLinesMap["entity"] = outerCommonTpls
	}

	pcode.ouStructTplDbsMaps = outPkgPbLinesMap

	return nil
}

func genTplFile(base string, pcode *PCode) error {
	module := pcode.p.name
	pkgPbDir := "pb" + module
	tpl := base + "/" + pkgPbDir
	//tplCommon := base + "/pbcommon"
	tplCommon := tpl

	//dto
	apiDtoStr := strings.Join(pcode.allPbLines, "\n")
	err := ioutil.WriteFile(fmt.Sprintf("%s/%s_api.tpl.proto", tpl, module), []byte(apiDtoStr), 0644)
	if err != nil {
		println(err.Error())
	}

	//api
	apiCommonStr := strings.Join(pcode.innerStructsPbTpls, "\n")
	err = ioutil.WriteFile(fmt.Sprintf("%s/%s_dto.tpl.proto", tpl, module), []byte(apiCommonStr), 0644)
	if err != nil {
		println(err.Error())
	}

	//common
	for pName, items := range pcode.ouStructTplDbsMaps {
		commonStr := strings.Join(items, "\n")
		err = ioutil.WriteFile(fmt.Sprintf("%s/%s_entity.tpl.proto", tplCommon, pName), []byte(commonStr), 0644)
		if err != nil {
			println(err.Error())
		}
	}

	//tplFiles := []string{tplHead}
	//tplFiles = append(tplFiles, pcode.proxyAPIsDefs...)
	//err := ioutil.WriteFile(filePre+"_basic_api.go", []byte(strings.Join(tplFiles, "\n")), 0644)
	//if err != nil {
	//	return err
	//}
	//
	//dtoFiles := []string{tplHead}
	//dtoFiles = append(dtoFiles, pcode.proxySrcPkgAPIStructs...)
	//err = ioutil.WriteFile(filePre+"_basic_dto.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	//if err != nil {
	//	return err
	//}
	return nil
}

//request and resp
func genAPIPbTpls(pb *BASICAPI, packageMap map[string]*Package) []string {
	reqs := genPbReqMessage(pb, packageMap)
	respLines := genPbRespMessage(pb, packageMap)

	return append(reqs, respLines...)
}

func genPbRespMessage(pb *BASICAPI, packageMap map[string]*Package) []string {
	api := pb.api
	if itemMap, ok := tplCodeMap[api.Module()]; ok {
		code := itemMap[api.pbRespSign()]
		if len(code) > 0 {
			return []string{code}
		}
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("message %sResponse{", pb.api.Method))

	for i, field := range pb.RespTypeStr {
		if field == "*wmserror.WMSError" {
			continue
		}
		fieldType := field
		//if strings.Contains(field, ".") {
		//	fieldType = strings.Split(field, ".")[1]
		//}
		alias := fmt.Sprintf("Ret%d", i+1)
		item := fmt.Sprintf("%s %s %s = %d;", toPbOption(field), toPbType(fieldType, packageMap), ToSnakeCase(alias), i+1)
		lines = append(lines, item)
	}
	lines = append(lines, "}")
	return lines
}

func genPbReqMessage(pb *BASICAPI, packageMap map[string]*Package) []string {
	api := pb.api
	if itemMap, ok := tplCodeMap[api.Module()]; ok {
		code := itemMap[api.pbReqSign()]
		if len(code) > 0 {
			return []string{code}
		}
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("message %sRequest{", pb.api.Method))
	isNotContainContext := len(pb.ReqFields) > 0 && pb.ReqFields[0].Type != "context.Context"
	for i, field := range pb.ReqFields {
		if field.Type == "context.Context" {
			continue
		}

		idx := i
		if isNotContainContext {
			idx += 1
		}

		item := fmt.Sprintf("%s %s %s = %d;", toPbOption(field.Type), toPbType(field.Type, packageMap), ToSnakeCase(field.Alias), idx)
		lines = append(lines, item)
	}
	lines = append(lines, "}")
	return lines
}

func convertoBasicType(fType string, pkgMap map[string]*Package) string {
	if !strings.Contains(fType, ".") {
		return fType
	}
	if pkgMap == nil {
		return fType
	}

	actualType := strings.ReplaceAll(strings.ReplaceAll(fType, "[]", ""), "*", "")

	segs := strings.Split(actualType, ".")
	typePackage := strings.ReplaceAll(segs[0], "*", "")
	//只支持constant类型转换
	if typePackage != "constant" {
		return fType
	}

	for packagePath, p := range pkgMap {
		pathSegs := strings.Split(packagePath, "/")
		if pathSegs[len(pathSegs)-1] == typePackage {
			ktype, err := p.FindType(segs[1])
			if err == nil {
				ctType := ktype.def.String()
				println(fmt.Sprintf("keyType:%s convert to %s", fType, ctType))
				return ctType
			}
		}
	}

	return fType

}
func toPbType(fType string, packageMap map[string]*Package) string {
	fieldType := convertoBasicType(fType, packageMap)

	if fieldType == "*pbshop.ExportShopRequest" {
		return "ExportShopRequestItem"
	}
	if fieldType == "string" {
		return "string"
	}
	if fieldType == "bool" || fieldType == "*bool" {
		return "bool"
	}
	if fieldType == "float64" || fieldType == "*float64" {
		return "float"
	}
	if fieldType == "uint64" || fieldType == "[]uint64" {
		return "uint64"
	}
	if fieldType == "[]string" || fieldType == "*string" {
		return "string"
	}
	if fieldType == "map[int64]*entity.CategoryWhsAttr" {
		return "MapCategoryWhsAttrItem"
	}
	if fieldType == "map[string]string" {
		return "MapItem"
	}
	if fieldType == "map[string]bool" {
		return "MapItem"
	}
	if fieldType == "map[string][]string" {
		return "MapStrsItem"
	}
	if fieldType == "map[uint64]int64" {
		return "MapUint64Item"
	}
	if fieldType == "map[string][]int6" {
		return "MapUint64Item"
	}
	if fieldType == "map[SupplierIDType]SupplierNameType" {
		return "MapItem"
	}
	if fieldType == "*collection.StringSet" {
		return "string"
	}
	if fieldType == "map[string][]*entity.SKUTagEntity" {
		return "MapSKUTagsItem"
	}
	if fieldType == "map[int64][]string" {
		return "MapIntStrsItem"
	}
	if fieldType == "db_config.Option" {
		return "Option"
	}
	if fieldType == "map[string][]int64" {
		return "MapIntsItem"
	}
	if fieldType == "map[string]constant.SkuSizeType" {
		return "MapItem"
	}
	if fieldType == "[]int64" || fieldType == "int" {
		return "int64"
	} else if fieldType == "int64" {
		return "int64"
	} else if strings.Contains(fieldType, "[]") {
		return toPbSliceStructItemType(fieldType)
	}
	switch fieldType {
	case "string":
		return "string"
	case "int64":
		return "int64"
	case "uint64":
		return "uint64"
	case "map[string]interface{}":
		return "MapItem"
	default:
		ftype := strings.ReplaceAll(fieldType, "*", "")
		if strings.Contains(ftype, ".") {
			return strings.Split(ftype, ".")[1] + "Item"
		}
		return ftype + "Item"
	}
}

func toPbSliceStructItemType(fieldType string) string {
	actualType := strings.ReplaceAll(strings.ReplaceAll(fieldType, "[]", ""), "*", "")
	split := strings.Split(actualType, ".")
	pType := actualType
	if len(split) > 1 {
		pType = split[1]
	}
	return pType + "Item"
}

func assignToPbType(field *ReqField) string {
	pbType := field.Type

	fieldType := pbType
	if fieldType == "string" {
		return fmt.Sprintf("convert.String(%s)", field.Alias)
	}
	if fieldType == "[]string" {
		return field.Alias
	}
	if fieldType == "[]int64" {
		return field.Alias
	} else if fieldType == "int64" {
		return fmt.Sprintf("convert.Int64(%s)", field.Alias)

	} else if fieldType == "MapItem" {
		return "mapItemLists"
	} else if fieldType == "map[string]interface{}" {
		return "mapItemLists"
	} else if isSturctItems(fieldType) {
		return fmt.Sprintf("%sItems", field.Alias)
	}

	return fmt.Sprintf("%sItem", field.Alias)
}

//func convertToPbType(fieldType, val string) string {
//
//	if fieldType == "string" {
//		return fmt.Sprintf("convert.String(%s)", val)
//	}
//	if fieldType == "[]string" {
//		return val
//	}
//	if fieldType == "bool" {
//		return val
//	}
//	if fieldType == "[]int64" {
//		return val
//	} else if fieldType == "int64" {
//		return fmt.Sprintf("convert.Int64(%s)", val)
//
//	} else if fieldType == "MapItem" {
//		return "mapItemLists"
//	} else if fieldType == "map[string]interface{}" {
//		return "mapItemLists"
//	} else if isSturctItems(fieldType) {
//		return fmt.Sprintf("%sItems", val)
//	}
//
//	return fmt.Sprintf("%sItem", val)
//}

func (field *ReqField) assignToPbTypeAlias() string {
	pbType := field.Type

	fieldType := pbType
	val := field.Alias
	//if ContainStr(pbType,"map["){
	//	val = con
	//}
	return convertToPbType(fieldType, val)
}

func convertToPbType(fieldType string, val string) string {
	if fieldType == "string" {
		return fmt.Sprintf("convert.String(%s)", val)
	}
	if fieldType == "[]string" {
		return val
	}
	if fieldType == "*string" {
		return val
	}
	if fieldType == "uint64" {
		return fmt.Sprintf("convert.UInt64(%s)", val)
	}
	if fieldType == "[]uint64" {
		return val
	}
	if fieldType == "bool" {
		return fmt.Sprintf("convert.Bool(%s)", val)
	}
	if fieldType == "int" {
		return fmt.Sprintf("convert.Int64(int64(%s))", val)
	}
	if fieldType == "[]int64" {
		return val
	} else if fieldType == "int64" {
		return fmt.Sprintf("convert.Int64(%s)", val)

	} else if fieldType == "MapItem" {
		return "mapItemLists"
	} else if fieldType == "map[string]interface{}" {
		return "mapItemLists"
	} else if isSturctItems(fieldType) {
		return fmt.Sprintf("%sItems", val)
	}

	return fmt.Sprintf("%sItem", val)
}

func isSturctItems(fieldType string) bool {
	isBasicType := strings.Contains(fieldType, "int64") ||
		strings.Contains(fieldType, "string") ||
		strings.Contains(fieldType, "uint64")
	return strings.Contains(fieldType, "[]") &&
		!isBasicType
}

func isInPkgSturctItem(fieldType string) bool {
	realType := strings.ReplaceAll(strings.ReplaceAll(fieldType, "[]", ""), "*", "")

	return !isNormalType(realType) && !strings.Contains(realType, ".")
}

func parseInnerStruct(uniqTypes []string, pcode *PCode, packageMap map[string]*Package) ([]string, map[string][]*JsonTag) {
	var itemTypes []ItemType
	for _, uniqType := range uniqTypes {
		itemTypes = append(itemTypes, ItemType(uniqType))
	}
	inItemStrs := []string{}
	inItemTagsMap := map[string][]*JsonTag{}
	notExistType := hashset.New()
	for _, itemType := range itemTypes {
		if itemType.IsInnerStruct() {
			inItemStrs = append(inItemStrs, string(itemType))
			for _, file := range pcode.p.files {
				itemTypeStr := strings.ReplaceAll(string(itemType), "*", "")
				itemTypeStr = strings.ReplaceAll(string(itemTypeStr), "[]", "")
				t, err := file.FindType(itemTypeStr)
				if err != nil && strings.Contains(err.Error(), "is not found") {
					//println(itemType, "is not found")
					notExistType.Add(itemType)
					continue
				}
				//for _, field := range t.def.(*StructType).Fields() {
				//	println(field.Definition().String())
				//}
				if _, ok := t.def.(*StructType); !ok {
					if notExistType.Contains(itemType) {
						continue
					}
					notExistType.Add(itemType)
					println(itemType, "is basic type")
					continue
				}
				for _, field := range t.def.(*StructType).fields {
					inItemTagsMap[itemTypeStr] = append(inItemTagsMap[itemTypeStr], NewJsonTag(field, packageMap))
				}
				if notExistType.Contains(itemType) {
					notExistType.Remove(itemType)
				}
				originDef := t.Definition().String()
				withoutHeadDef := strings.ReplaceAll(originDef, "struct {", fmt.Sprintf("struct %s{", itemTypeStr))
				//def = append(def, withoutHeadDef)
				println(withoutHeadDef)
				//println(t)
			}
		}
	}
	println("not exist item type:\n", ToPrettyJSON(notExistType.Values()))
	return inItemStrs, inItemTagsMap
}

func parseOuterStruct(uniqTypes []string, pcode *PCode, packageMap map[string]*Package) ([]string, map[string][]*JsonTag) {
	var itemTypes []ItemType
	for _, uniqType := range uniqTypes {
		itemTypes = append(itemTypes, ItemType(uniqType))
	}
	inItemStrs := []string{}
	outItemTagsMap := map[string][]*JsonTag{}
	for _, itemType := range itemTypes {
		if itemType.IsOuterStruct() {
			actualType := strings.ReplaceAll(strings.ReplaceAll(itemType.String(), "[]", ""), "*", "")
			actualType = strings.ReplaceAll(actualType, "map[string]", "")
			actualType = strings.ReplaceAll(actualType, "map[int64]", "")
			actualType = strings.ReplaceAll(actualType, "map[uint64]", "")

			segs := strings.Split(actualType, ".")
			typePackage := strings.ReplaceAll(segs[0], "*", "")
			for packagePath, p := range packageMap {
				pathSegs := strings.Split(packagePath, "/")
				if pathSegs[len(pathSegs)-1] == typePackage {
					ktype, err := p.FindType(segs[1])
					if err != nil && strings.Contains(err.Error(), "is not found") {
						//println(itemType, "is not found")
						continue
					}

					if structType, ok := ktype.def.(*StructType); ok {
						inItemStrs = append(inItemStrs, actualType)
						if _, exist := outItemTagsMap[actualType]; exist {
							continue
						}
						for _, field := range structType.fields {
							outItemTagsMap[actualType] = append(outItemTagsMap[actualType], NewJsonTag(field, packageMap))
						}
					} else {
						println("out struct is not a struct type; %s", itemType)
					}
				}
			}
			for _, file := range pcode.p.files {
				itemTypeStr := strings.ReplaceAll(string(itemType), "*", "")
				t, err := file.FindType(itemTypeStr)
				if err != nil && strings.Contains(err.Error(), "is not found") {
					//println(itemType, "is not found")
					continue
				}
				//for _, field := range t.def.(*StructType).Fields() {
				//	println(field.Definition().String())
				//}
				for _, field := range t.def.(*StructType).fields {
					outItemTagsMap[itemTypeStr] = append(outItemTagsMap[itemTypeStr], NewJsonTag(field, packageMap))

				}
				originDef := t.Definition().String()
				withoutHeadDef := strings.ReplaceAll(originDef, "struct {", fmt.Sprintf("struct %s{", itemTypeStr))
				//def = append(def, withoutHeadDef)
				println(withoutHeadDef)
				//println(t)
			}
		}
	}
	return inItemStrs, outItemTagsMap
}

func getStructTypeSet(tagsMap map[string][]*JsonTag) []string {
	var items []string
	for _, tags := range tagsMap {
		for _, tag := range tags {
			items = append(items, tag.KeyType)
		}
	}
	return uniqSlice(items...)
}

func genTplByJsonTagsMap(tagsMap map[string][]*JsonTag) []string {

	var items []string
	for objName, tags := range tagsMap {
		item := []string{}
		tplHead := fmt.Sprintf("message  %sItem{", objName)
		var pbFields = []string{}
		for i, tag := range tags {
			fieldStr := tag.ToPbFieldDef(i)
			pbFields = append(pbFields, fieldStr)
		}
		tplFoot := fmt.Sprintf("}")

		item = append(item, tplHead)
		item = append(item, pbFields...)
		item = append(item, tplFoot)
		items = append(items, strings.Join(item, "\n"))
	}
	return items
}

func genOuterTplByJsonTagsMap(tagsMap map[string][]*JsonTag) map[string][]string {

	var retItemMaps = map[string][]string{}
	for objName, tags := range tagsMap {
		segs := strings.Split(objName, ".")
		packageName := segs[0]
		vType := segs[1]
		var item []string
		tplHead := fmt.Sprintf("message  %sItem{", vType)
		var pbFields = []string{}
		for i, tag := range tags {
			fieldStr := tag.ToPbFieldDef(i)
			pbFields = append(pbFields, fieldStr)
		}
		tplFoot := fmt.Sprintf("}")

		item = append(item, tplHead)
		item = append(item, pbFields...)
		item = append(item, tplFoot)
		retItemMaps[packageName] = append(retItemMaps[packageName], item...)
	}
	return retItemMaps
}

type JsonTag struct {
	Key     string
	KeyType string
	JsonTag string
	isValid bool
}

func (t JsonTag) ToPbFieldDef(keyIdex int) string {
	return fmt.Sprintf("%s %s %s = %d;", t.ToPbOption(), t.toPbType(), t.Key, keyIdex+1)
}

func (t JsonTag) ToPbOption() string {
	return toPbOption(t.KeyType)
}

func toPbOption(t string) string {
	if strings.Contains(t, "[") {
		return "repeated"
	}
	if strings.Contains(t, "collection.") {
		return "repeated"
	}
	return "optional"
}

func (t JsonTag) toPbType() string {
	fieldType := strings.ReplaceAll(t.KeyType, "*", "")
	fieldType = strings.ReplaceAll(fieldType, "[]", "")

	return toPbType(fieldType, nil)
}

//tag: like json:"whs_id,omitempty"
func NewJsonTag(field *Field, packageMap map[string]*Package) *JsonTag {
	tag := field.Tags()
	keyType := field.def.String()
	key := strings.Split(tag.Get("json"), ",")[0]
	//segs := strings.Split(tag, ":")
	//isValid := true
	//if len(segs) != 2 || segs[0] != "json" {
	//	isValid = false
	//}
	//tagVal := segs[1]
	//tagValWithoutEmpty := strings.ReplaceAll(tagVal, "\"", "")
	//
	//key := strings.Split(tagValWithoutEmpty, ",")[0]

	//如： "*constant.SkuSizeType", 转换成int64\或者string
	if strings.Contains(keyType, ".") {
		keyType = strings.ReplaceAll(strings.ReplaceAll(keyType, "[]", ""), "*", "")
		segs := strings.Split(keyType, ".")
		typePackage := segs[0]
		for packagePath, p := range packageMap {
			pathSegs := strings.Split(packagePath, "/")
			if pathSegs[len(pathSegs)-1] == typePackage {
				ktype, err := p.FindType(segs[1])
				if err == nil {
					ctType := ktype.name
					if strings.Contains(ctType, "entity") {
						ctType = strings.ReplaceAll(ctType, "entity.", "")
					}
					if strings.Contains(ctType, "message") {
						ctType = strings.ReplaceAll(ctType, "message.", "")
					}
					if strings.Contains(typePackage, "constant") {
						ctType = ktype.def.String()
					}
					println(fmt.Sprintf("keyType:%s convert to %s", keyType, ctType))
					keyType = ctType
				}
			}
		}
	}

	isValid := len(key) > 0

	return &JsonTag{
		Key:     key,
		KeyType: keyType,
		isValid: isValid,
	}
}

func uniqSlice(types ...string) []string {
	set := hashset.New()
	for _, s := range types {
		set.Add(s)
	}

	var ret []string
	for _, i := range set.Values() {
		ret = append(ret, i.(string))
	}
	return ret
}

func genSrcProxyCodeFile(conf *CodeGenConf, pcode *PCode) error {
	module := pcode.p.name
	filePre := conf.srcBase + "/" + module

	packageHead := fmt.Sprintf("package %s", module)
	apiFiles := []string{packageHead}
	apiFiles = append(apiFiles, pcode.srcPkgProxyFuncs...)
	err := ioutil.WriteFile(filePre+"_proxy_handler.go", []byte(strings.Join(apiFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	//proxy main.go
	proxyMain := []string{packageHead}

	val := "const module = \"%s\"\n\nvar apiIdempotent = wmsbasicproxy.APIIdempotent()\n\nfunc getBasicHandler() wmsbasicproxy.BasicProxyHandler {\n\treturn wmsbasicproxy.GetModuleHandler(module)\n}\n"
	proxyMain = append(proxyMain, fmt.Sprintf(val, module))
	//
	//type HighValueManagerProxy struct {
	//	highValueManager         HighValueManager
	//	highValueManagerProxyAPI wmsbasic.MhighvalueAPI
	//}
	proxyMain = append(proxyMain, fmt.Sprintf("type %sProxy struct{", upFirstChar(conf.targetStruct)))
	proxyMain = append(proxyMain, fmt.Sprintf("\t %s %s", lowerFirstChar(conf.targetStruct), conf.targetStruct))
	proxyMain = append(proxyMain, fmt.Sprintf("\t %sProxyAPI wmsbasic.%sAPI", lowerFirstChar(conf.targetStruct), upFirstChar(module)))
	proxyMain = append(proxyMain, "}")

	//err = ioutil.WriteFile(filePre+"_proxy_main.go", []byte(strings.Join(proxyMain, "\n")), 0644)
	//if err != nil {
	//	return err
	//}
	return nil
}

type SrcEndPoint string

func NewSrcEndPoint(p, f string) SrcEndPoint {
	return SrcEndPoint(fmt.Sprintf("%s#%s", p, f))
}

type PCode struct {
	p *Package
	//代理包定义
	srcPkgProxyFuncs []string
	//源包代理方法体
	srcPkgProxyFuncMap map[SrcEndPoint]string

	outStructList []string
	//代理的包纬度接口定义
	proxyAPIsDefs []string
	//代理的包纬度接口struct
	proxySrcPkgAPIStructs []string

	//所有的API
	basicAPIPbs []*BASICAPI

	basicAPIDefMap  map[SrcEndPoint]string
	basicAPIReqsMap map[SrcEndPoint]string
	basicAPIPbsMap  map[SrcEndPoint]*BASICAPI

	//API 对应的pb定义
	allPbLines         []string
	apiPbLinesMap      map[string][]string
	innerStructTypes   []string
	inItemTagsMap      map[string][]*JsonTag
	innerStructsPbTpls []string

	//outer struct
	ouStructTplDbsMaps map[string][]string
	conf               *CodeGenConf
	pkgMap             map[string]*Package
}

func (pcode PCode) genProxyAPIStructDefAndConstruct() string {
	pkgName := pcode.p.name
	actualApiName := fmt.Sprintf("%sBasicAPI", upFirstChar(pkgName))
	apiName := fmt.Sprintf("%sAPI", upFirstChar(pkgName))
	objSign := fmt.Sprintf(" type %s struct{", actualApiName)
	objSign += "\n\t Client Client"
	objSign += "\n\t }"
	//func NewMsizetypeBasicAPI() *MsizetypeBasicAPI {
	//	return &MsizetypeBasicAPI{}
	//}

	objConsturcts := []string{}
	newStr := fmt.Sprintf("func New%s() %s {", apiName, apiName)
	returnStr := fmt.Sprintf("return &%s{", actualApiName)
	returnStr += "\n\tClient: NewClient(),"
	returnStr += "\n\t}"

	objConsturcts = append(objConsturcts, newStr)
	objConsturcts = append(objConsturcts, returnStr)
	objConsturcts = append(objConsturcts, "}")

	return objSign + "\n" + strings.Join(objConsturcts, "\n")

}

func parsePCode(p *Package, packageMap map[string]*Package, conf *CodeGenConf) *PCode {
	code := &PCode{
		p: p,
	}
	inStructSet := hashset.New()
	outStructSet := hashset.New()
	apis := parseFuncs(p, inStructSet, outStructSet, packageMap)

	var funcDefs []string
	var basicAPIs []string
	var basicAPIReqs []string
	var basicAPIPbs []*BASICAPI

	var apiFuncDefsMap = map[SrcEndPoint]string{}
	var basicAPIsMap = map[SrcEndPoint]string{}
	var basicAPIReqsMap = map[SrcEndPoint]string{}
	var basicAPIPbsMap = map[SrcEndPoint]*BASICAPI{}
	//sort
	sort.Slice(apis, func(i, j int) bool {
		return apis[i].Method < apis[j].Method
	})

	for _, api := range apis {
		if !isExported(api.Method) {
			//println("method is not exported: ", api.Method)
			continue
		}

		if !api.isNeedProxy() {
			println("no need to proxy", api.Method)
			continue
		}
		//isNeedHandler := isNeedToHandler(api, conf)
		//if !isNeedHandler {
		if !api.isNeedHandler(conf) {
			receiverName := api.ReceiverName
			println(fmt.Sprintf("receiverName %s is no need to handler", receiverName))
			continue
		}
		endpoint := NewSrcEndPoint(api.Pkg.name, api.Method)
		funcDefs = append(funcDefs, api.proxyFuncBody2())
		apiFuncDefsMap[endpoint] = api.proxyFuncBody2()

		basicAPIs = append(basicAPIs, api.BasicAPIInterfaceSignWithComment())
		basicAPIsMap[endpoint] = api.BasicAPIInterfaceSignWithComment()

		basicAPIReqs = append(basicAPIReqs, api.proxyPbAPIReq())
		basicAPIReqsMap[endpoint] = api.proxyPbAPIReq()

		basicAPIPbs = append(basicAPIPbs, api.proxyPbAPI())
		basicAPIPbsMap[endpoint] = api.proxyPbAPI()
	}

	code.srcPkgProxyFuncMap = apiFuncDefsMap
	code.basicAPIDefMap = basicAPIsMap

	code.basicAPIReqsMap = basicAPIReqsMap
	code.basicAPIPbsMap = basicAPIPbsMap

	//prttryStr("func body", strings.Join(funcDefs, "\n"))
	code.proxyAPIsDefs = buildPackageProxyBasicAPI(code)
	code.basicAPIPbs = basicAPIPbs
	//源包
	code.srcPkgProxyFuncs = funcDefs
	//代理包
	code.proxySrcPkgAPIStructs = pReqItemStrs(apis)

	//prttryStr("basic api ", strings.Join(basicAPIs, "\n\n"))
	//prttryStr("basic api req", strings.Join(basicAPIReqs, "\n\n"))
	var outStructTypeList []string
	var inStructTypeList []string
	for _, i := range inStructSet.Values() {
		ftype := i.(string)
		if isNormalType(ftype) || strings.Contains(ftype, ".") {
			continue
		}

		inStructTypeList = append(inStructTypeList, ftype)
		//println(p.name, " inner struct", ftype)
	}
	code.innerStructTypes = inStructTypeList

	checkNeedAddJsonTag(p, inStructTypeList)

	for _, i := range outStructSet.Values() {
		//println(p.name, " out struct", i.(string))
		outStructTypeList = append(outStructTypeList, i.(string))
	}
	code.outStructList = outStructTypeList

	return code

}

func checkNeedAddJsonTag(p *Package, inStructTypeList []string) {
	needAddJsonTagTypes := []string{}
	for _, ftype := range inStructTypeList {
		t, err := p.FindType(ftype)
		if err != nil && strings.Contains(err.Error(), "is not found") {
			continue
		}
		if objType, ok := t.def.(*StructType); ok {
			for _, field := range objType.fields {

				key := strings.Split(field.tags.Get("json"), ",")[0]
				if key == "" {
					needAddJsonTagTypes = append(needAddJsonTagTypes, ftype)
				}
			}
		}

	}

	println("need add json tag structs:", ToPrettyJSON(uniqSlice(needAddJsonTagTypes...)))
}

func pReqItemStrs(apis []*API) []string {
	reqDefSet := hashset.New()
	for _, api := range apis {
		if !isExported(api.Method) {
			continue
		}
		for _, itemStr := range api.proxyProxyAPIReqItem() {
			reqDefSet.Add(itemStr)
		}
	}
	reqItems := []string{}
	for _, i := range reqDefSet.Values() {
		reqItems = append(reqItems, i.(string))
	}
	return reqItems
}

func buildPackageProxyBasicAPI(pcode *PCode) []string {
	var basicAPISign []string
	for _, sign := range pcode.basicAPIDefMap {
		basicAPISign = append(basicAPISign, sign)
	}
	sort.Slice(basicAPISign, func(i, j int) bool {
		return basicAPISign[i] < basicAPISign[j]
	})

	var wmsbasicAPI []string
	wmsbasicAPI = append(wmsbasicAPI, fmt.Sprintf("type %sAPI interface {", upFirstChar(pcode.p.name)))
	wmsbasicAPI = append(wmsbasicAPI, basicAPISign...)
	wmsbasicAPI = append(wmsbasicAPI, "}")
	return wmsbasicAPI
}

func parseFuncs(p *Package, inStructSet *hashset.Set, outStructSet *hashset.Set, packageMap map[string]*Package) []*API {
	var apis []*API
	for _, function := range p.Functions() {
		receiver := function.receiver
		//todo filter proxy_main 方法

		if receiver == nil {
			println(function.name, " is not receiver")
			continue
		}
		if strings.Contains(strings.ToLower(function.file.fileName), "proxy") {
			continue
		}
		//like skuManager
		originObjName := receiver.def.String()
		receiverName := originObjName + "Proxy"
		receiverAlias := receiver.name
		funcWithReciver := fmt.Sprintf("func (%v %s) ", receiverAlias, receiverName) + function.name
		getDefinitionWithName := function.def.getDefinitionWithName(funcWithReciver)
		//println("getDefinitionWithName:=", getDefinitionWithName)

		api := genReqAndResp(function, packageMap)
		api.FuncSignStr = getDefinitionWithName
		api.ReceiverAlias = receiverAlias
		api.ReceiverName = strings.ReplaceAll(originObjName, "*", "")
		api.Pkg = p
		apis = append(apis, api)

		//println(ToPrettyJSON(api))

		for _, i := range api.genInnerDefPkgStructs() {
			inStructSet.Add(i)
		}
		for _, i := range api.genOuterDefPkgStructs() {
			outStructSet.Add(i)
		}
	}
	return apis
}

func prttryStr(label string, body string) {
	println()
	println(color.InGreen(fmt.Sprintf("====================== [%s] start =====================", label)))
	println(body)
	println(color.InGreen(fmt.Sprintf("====================== [%s] end =====================", label)))
	println()

}

type API struct {
	//apps/config/manager/mlifecyclerule
	Path    string
	Package string
	// SearchAllTaskSizeType
	Method        string
	Req           map[string]string
	ReqFields     []*ReqField
	Resp          []string
	Func          *FuncType
	FuncSignStr   string
	ReceiverAlias string
	ReceiverName  string
	Pkg           *Package
	genBasicV2Err bool
	pkgMap        map[string]*Package
	RespItems     []*RespField
}

type BASICAPI struct {
	Path    string
	Package string
	//POST 还是GET
	Method      string
	Req         map[string]string
	ReqFields   []*ReqField
	RespTypeStr []string
	Pkg         *Package
	api         API
}

func (b BASICAPI) ProxyOpenapiMethod() string {
	routerMethod := "RegisterGetOpenApiURL"
	if b.Method == "POST" {
		routerMethod = "RegisterPostOpenApiURL"
	}
	return routerMethod

}

func (b BASICAPI) invokeAlias() []string {
	var items []string
	for _, field := range b.ReqFields {
		if field.isContext() {
			items = append(items, field.Alias)
		} else {
			items = append(items, field.aliasDef())

		}
	}
	return items
}

func (b BASICAPI) viewInvokeAlias() []string {
	var items []string
	for _, field := range b.ReqFields {
		items = append(items, field.formatFieldAlias())
	}
	return items
}
func (b BASICAPI) viewInvokeAliasWithoutCtx() []string {
	var items []string
	for _, field := range b.ReqFields {
		if field.isContext() {
			continue
		}
		items = append(items, field.formatFieldAlias())
	}
	return items
}

func (b BASICAPI) viewHandlerErr() string {
	var lines []string
	lines = append(lines, "if err!=nil {")
	lines = append(lines, "return nil, err.Mark()")
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}

func (b API) viewHandlerErr() string {

	var lines []string
	lines = append(lines, "if err!=nil {")
	//lines = append(lines, "return nil, err.Mark()")
	valLine := fmt.Sprintf("return %s,err.Mark()", strings.Join(b.apiReqAliasWithoutCtxDeafultVal(), ","))
	lines = append(lines, valLine)
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}

func (b API) viewHandlerJsErr() string {

	var lines []string
	//lines = append(lines, "return nil, err.Mark()")
	valLine := fmt.Sprintf("return %s, wmserror.NewError(constant.ErrJsonDecodeFail,jsErr.Error())", strings.Join(b.apiReqAliasWithoutCtxDeafultVal(), ","))
	lines = append(lines, valLine)
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}

type ReqField struct {
	Alias string
	Type  string
}

type RespField struct {
	Alias string
	Type  string
}

func (f *RespField) IsNormalType() bool {
	return isNormalType(f.Type)
}

func (f *RespField) isItemSlice() bool {
	return strings.HasPrefix(f.Type, "[]*")
}

func (f *RespField) ObjType() string {
	type1 := strings.ReplaceAll(strings.ReplaceAll(f.Type, "*", ""), "[]", "")
	return type1
}

func (f ReqField) defNormalTypeSign() string {
	return fmt.Sprintf("var %s %s", f.aliasDef(), f.Type)
}
func (f ReqField) defTypeSign() string {
	return fmt.Sprintf("var %s %s", f.aliasDef(), f.Type)
}

func (f ReqField) defSturctType() string {
	return fmt.Sprintf("var %s %s", f.aliasDef(), f.Type)
}

func (f ReqField) defSturctSliceType() string {
	return fmt.Sprintf("var %s %s", f.aliasDef(), f.Type)
}

func (f ReqField) aliasDef() string {
	if isNormalType(f.Type) {
		return f.Alias
	} else {
		if isSturctItems(f.Type) {
			return f.Alias + "Items"
		} else {
			return f.Alias + "Item"
		}
	}
}

func (f ReqField) isContext() bool {
	return f.Type == "context.Context"

}

func (f ReqField) isPageInItem() bool {
	return f.Type == "*paginator.PageIn"
}

func (f ReqField) isUpdateMap() bool {
	return f.Type == "map[string]interface{}"
}

func (f ReqField) convertPageInAssignLines(module string) []string {
	field := &f
	var lines []string
	pbType := assignToPbType(field)
	lines = append(lines, fmt.Sprintf("%s:=&pb%s.%s{", pbType, module, toPbSliceStructItemType(field.Type)))
	//		Pageno:     convert.Int64(pageIn.Pageno),
	//		Count:      convert.Int64(pageIn.Count),
	//		OrderBy:    convert.String(pageIn.OrderBy),
	//		IsGetTotal: convert.Bool(pageIn.IsGetTotal),
	alias := field.Alias
	lines = append(lines, fmt.Sprintf("\tPageno:     convert.Int64(%s.Pageno),", alias))
	lines = append(lines, fmt.Sprintf("\tCount:     convert.Int64(%s.Count),", alias))
	lines = append(lines, fmt.Sprintf("\tOrderBy:     convert.String(%s.OrderBy),", alias))
	lines = append(lines, fmt.Sprintf("\tIsGetTotal:     convert.Bool(%s.IsGetTotal),", alias))
	lines = append(lines, "}")
	return lines
}

func (f ReqField) convertPbToBasic(module string) []string {
	field := &f
	var lines []string
	line := `
	var %s *paginator.PageIn
	if pageInItem := req.PageIn; pageInItem != nil {
		%s = &paginator.PageIn{
			Pageno:     pageInItem.GetPageno(),
			Count:      pageInItem.GetCount(),
			OrderBy:    pageInItem.GetOrderBy(),
			IsGetTotal: pageInItem.GetIsGetTotal(),
		}
	}
`
	lines = append(lines, fmt.Sprintf(line, field.Alias, field.Alias))
	return lines
}

func (f ReqField) toPbDefItemOrItems(module string) []string {
	field := &f
	var params = []string{}
	pbType := assignToPbType(field)
	if isSturctItems(field.Type) {
		params = append(params, fmt.Sprintf("%s:=[]*pb%s.%s{}", pbType, module, toPbSliceStructItemType(field.Type)))
	} else {
		params = append(params, fmt.Sprintf("%s:=&pb%s.%s{}", pbType, module, toPbSliceStructItemType(field.Type)))
	}
	if field.Type == "[]constant.CategoryLevel" {
		return []string{fmt.Sprintf("%s:=[]int64{}", pbType)}

	}
	return params

}
func (f ReqField) toDefItemOrItemsWithoutInit(module string) []string {
	field := &f
	var params = []string{}
	pbType := assignToPbType(field)
	if isSturctItems(field.Type) {
		params = append(params, fmt.Sprintf("%s:=[]*pb%s.%s{}", pbType, module, toPbSliceStructItemType(field.Type)))
	} else {
		params = append(params, fmt.Sprintf("%s:=&pb%s.%s{}", pbType, module, toPbSliceStructItemType(field.Type)))
	}
	return params

}
func (f ReqField) toDefBasicItemOrItems(module string) []string {
	field := &f
	var params = []string{}
	if strings.Contains(field.Type, ".") {
		if strings.Contains(field.Type, "[]") {
			return []string{fmt.Sprintf("%s=%s{}", field.formatFieldAlias(), field.Type)}
		} else {
			type1 := strings.ReplaceAll(field.Type, "*", "")
			return []string{fmt.Sprintf("%s=&%s{}", field.formatFieldAlias(), type1)}
		}
	}

	//eg 请求参数为:[]*msizetype.conditions
	type1 := strings.ReplaceAll(strings.ReplaceAll(field.Type, "*", ""), "[]", "")
	if isSturctItems(field.Type) {
		params = append(params, fmt.Sprintf("%s=[]*%s.%s{}", field.formatFieldAlias(), module, type1))
	} else {
		if f.isPointer() {
			params = append(params, fmt.Sprintf("%s=&%s.%s{}", field.formatFieldAlias(), module, type1))
		}
	}
	return params

}

func (f ReqField) VarPbItem(isInit bool, api *API) []string {
	field := &f
	var params = []string{}

	if f.isNormalType() {
		return nil
	}

	//params = append(params, fmt.Sprintf("%s:=[]*pb%s.%s{}", pbType, module, ToPbItemType(field.Type)))
	if field.isStructSlice() {
		params = append(params, fmt.Sprintf("var %s []*%s", field.assignToPbTypeAlias(), field.ToPbItemType(api)))
	} else {
		if f.isPointer() {
			params = append(params, fmt.Sprintf("var %s *%s", field.assignToPbTypeAlias(), field.ToPbItemType(api)))
		} else {
			params = append(params, fmt.Sprintf("var %s %s", field.assignToPbTypeAlias(), field.ToPbItemType(api)))
		}
	}
	return params

}

func (f ReqField) VarItem(isInit bool, api *API) []string {
	field := &f
	var params = []string{}

	if f.isNormalType() {
		return nil
	}

	module := api.Module()
	//params = append(params, fmt.Sprintf("%s:=[]*pb%s.%s{}", pbType, module, ToPbItemType(field.Type)))
	if field.isStructSlice() {
		if ContainStr(field.ObjType(), ".") {
			params = append(params, fmt.Sprintf("var %s []*%s", field.Alias, field.ObjType()))
		} else {
			params = append(params, fmt.Sprintf("var %s []*%s.%s", field.Alias, module, field.ObjType()))
		}
	} else {
		if f.isPointer() {
			if ContainStr(field.ObjType(), ".") {
				params = append(params, fmt.Sprintf("var %s *%s", field.Alias, field.ObjType()))
			} else {
				params = append(params, fmt.Sprintf("var %s *%s.%s", field.Alias, module, field.ObjType()))
			}
		} else {
			params = append(params, fmt.Sprintf("var %s %s.%s", field.Alias, module, field.ObjType()))
		}
	}
	return params

}

func (f ReqField) formatFieldAlias() string {
	field := &f
	if field.Alias == "entity" {
		return "entityItem"
	}
	return field.Alias
}

func (f ReqField) genDealCopyJsErrLines(isDefineJsErr *bool, api API) []string {
	field := &f
	copyLine := "jsErr := copier.Copy(%s,%s)"
	var params []string
	pbType := assignToPbType(field)
	if *isDefineJsErr {
		copyLine = strings.ReplaceAll(copyLine, ":", "")
	} else {
		a := true
		isDefineJsErr = &a
	}
	params = append(params, fmt.Sprintf(copyLine, field.Alias, pbType))

	retItemVars := api.apiRets()
	errLines := dealCopyErrLines(retItemVars)
	params = append(params, errLines...)
	params = append(params, "}")
	return params
}

func (f ReqField) genDealCopyJsErrLinesWithConvert(api API) []string {
	field := &f
	var params []string
	if f.isNotPointerStruct() {
		copyLine := "if jsErr := copier.Copy(%s,&%s);jsErr!=nil{"
		pbType := assignToPbType(field)
		params = append(params, fmt.Sprintf(copyLine, field.Alias, pbType))

		retItemVars := api.apiRets()
		params = append(params, dealCopyErrLinesWithConvert(retItemVars)...)
		return params
	}

	if strings.HasPrefix(field.Type, "[]") {
		params = append(params, fmt.Sprintf("if len(%s)>0{", f.Alias))
	} else {
		params = append(params, fmt.Sprintf("if %s!=nil{", f.Alias))
	}
	lines := field.toPbDefItemOrItems(api.Pkg.name)
	removeRedef := []string{}
	for _, line := range lines {
		removeRedef = append(removeRedef, strings.ReplaceAll(line, ":", ""))
	}
	if field.Type != "[]constant.CategoryLevel" {
		params = append(params, removeRedef...)
	}

	copyLine := "if jsErr := copier.Copy(%s,%s);jsErr!=nil{"
	pbType := assignToPbType(field)
	params = append(params, fmt.Sprintf(copyLine, field.Alias, pbType))

	retItemVars := api.apiRets()
	params = append(params, dealCopyErrLinesWithConvert(retItemVars)...)
	params = append(params, "}")

	return params
}

func (field *ReqField) toPbType() interface{} {
	return toPbType(field.Type, nil)
}

func (field *ReqField) isPointer() bool {
	return strings.Contains(field.Type, "*")
}

func (field *ReqField) isNotPointerStruct() bool {
	return !strings.HasPrefix(field.Type, "*") &&
		!strings.HasPrefix(field.Type, "[]") &&
		!strings.HasPrefix(field.Type, "map[") &&
		!isNormalType(field.Type)
}

func (field *ReqField) isContainOutStruct() bool {
	return strings.Contains(field.Type, ".")
}

func (field *ReqField) wmsbasicUpdateMapToPbItemLines(api *API) []string {
	module := api.Pkg.name
	var params []string
	params = append(params, fmt.Sprintf("mapItems,err := convertToMapUpdateItems(%s)", field.Alias))

	params = append(params, "if err != nil {")
	params = append(params, "\t\treturn  nil,wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())")
	params = append(params, "}")
	params = append(params, fmt.Sprintf("mapItemLists := []*pb%s.MapItem{}", module))
	params = append(params, "cpErr := copier.Copy(mapItems, &mapItemLists)")
	params = append(params, "if cpErr != nil {")
	params = append(params, "\t\treturn  nil,wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", cpErr.Error())")
	params = append(params, "}")

	return params
}

func (field *ReqField) isNormalType() bool {
	type1 := field.ObjType()

	return isNormalType(type1)
}

func (field *ReqField) ObjType() string {
	type1 := strings.ReplaceAll(strings.ReplaceAll(field.Type, "*", ""), "[]", "")
	return type1
}

func (field *ReqField) isStructSlice() bool {
	return !field.isNormalType() && strings.Contains(field.Type, "[]")
}

func (field *ReqField) ToPbItemType(api *API) string {
	return fmt.Sprintf("pb%s.%s", api.Module(), toPbSliceStructItemType(field.ObjType()))
}

func (field *ReqField) toAssignPbItemVar(api *API, pbPkg *Package) string {
	pbType := api.parsePbFieldType(pbPkg, field)

	var item string

	if api.Method == "SearchHighValueByHvIds" && field.Alias == "isGlobal" {
		item = fmt.Sprintf("\t%s:%s,", pbType, "convert.Int64(isGlobal)")
	} else {
		if field.isNotPointerStruct() {
			if strings.Contains(field.assignToPbTypeAlias(), "mapItemLists") {
				item = fmt.Sprintf("\t%s:%s,", pbType, field.assignToPbTypeAlias())
			} else {
				if field.isNormalType() {
					item = fmt.Sprintf("\t%s:%s,", pbType, field.assignToPbTypeAlias())
				} else {
					item = fmt.Sprintf("\t%s:&%s,", pbType, field.assignToPbTypeAlias())
				}
			}
		} else {
			item = fmt.Sprintf("\t%s:%s,", pbType, field.assignToPbTypeAlias())
		}
	}

	if api.Method == "GetCategoryRepoWithGlobalFlagWithStatus" && field.Alias == "isGlobal" {
		item = fmt.Sprintf("\t%s:%s,", pbType, "convert.Int64(isGlobal)")
	}

	if field.Type == "constant.CategoryUpdateType" {
		item = fmt.Sprintf("\t%s:convert.Int64(%s),", pbType, field.Alias)
	}
	if field.Alias == "parent_category_id" {
		item = fmt.Sprintf("\t%s:convert.Int64(%s),", "ParentCategoryId", field.Alias)
	}
	if field.Type == "constant.SKUBlockType" {
		item = fmt.Sprintf("\t%s:convert.Int64(%s),", pbType, field.Alias)
	}
	if field.Type == "constant.IsPouchPackingStorageType" {
		item = fmt.Sprintf("\t%s:convert.Int64(%s),", pbType, field.Alias)
	}
	if field.Type == "constant.CategoryAttrUpdateTypeEnum" {
		item = fmt.Sprintf("\t%s:convert.Int64(%s),", pbType, field.Alias)
	}
	return item
}

func (field *ReqField) isSpec() bool {
	//pbType := toPbType(field.Type, nil)
	//if field.isNormalType() {
	//	return true
	//}
	//if field.isPageInItem() {
	//	return true
	//}
	//return ContainStr(pbType, "Map") && ContainStr(pbType, "Item")
	return !field.isNormalType()
}

func (api *API) proxyBasicFuncBody(pbPkg *Package, packageMap map[string]*Package) string {

	//module := api.Pkg.name
	var bodyStr []string

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var err *wmserror.WMSError

	retItems := api.apiRetDefs()

	bodyStr = append(bodyStr, retItems...)
	bodyStr = append(bodyStr, "")

	var params []string
	isDefineJsErr, preDefLines := api.genWmsV2ToBasicPreItemDefLines(packageMap)
	params = append(params, preDefLines...)

	params = append(params, "\n// do requets")
	params = append(params, fmt.Sprintf("req:=&%s{", api.apiPbReqType()))
	for _, field := range api.ReqFields {
		if field.Type == "context.Context" {
			continue
		}
		pbType := api.parsePbFieldType(pbPkg, field)

		//item := fmt.Sprintf("\t%s:%s,", pbType, assignToPbTypeAlias(field))
		var item string
		if api.Method == "SearchHighValueByHvIds" && field.Alias == "isGlobal" {
			item = fmt.Sprintf("\t%s:%s,", pbType, "convert.Int64(isGlobal)")
		} else {
			item = fmt.Sprintf("\t%s:%s,", pbType, field.assignToPbTypeAlias())
		}

		params = append(params, item)
	}
	params = append(params, "}")

	var resps []string
	resps = append(resps, fmt.Sprintf("resp:=&%s{}", api.apiPbRespType()))

	bodyStr = append(bodyStr, params...)
	bodyStr = append(bodyStr, resps...)

	method := api.genBasicAPIMethod()
	method = upFirstChar(strings.ToLower(method))
	bodyStr = append(bodyStr, fmt.Sprintf("\t_, err = m.Client.%s(ctx, %s, req, resp, DefaultTimeOut)", method, api.endpointEnum()))

	bodyStr = append(bodyStr, "\tif err != nil {")
	//	if err != nil {
	//		return err.Mark()
	//	}
	lines := api.genNormalErrLines()
	bodyStr = append(bodyStr, lines...)

	copyLine := "jsErr := copier.Copy(%s,%s)"

	retLines := api.assignReturnAssign(isDefineJsErr, copyLine)
	bodyStr = append(bodyStr, retLines...)

	returnVal := "\t\treturn   nil"
	if len(api.apiRets()) > 1 {
		errMsg := "\t\treturn  %s, nil"
		returnVal = fmt.Sprintf(errMsg, strings.Join(api.apiRets()[0:len(api.apiRets())-1], ","))
	}

	bodyStr = append(bodyStr, returnVal)

	bodyStr = append(bodyStr, "\t}")
	bodyStr = append(bodyStr, "\n")

	return strings.Join(bodyStr, "\n")
}

func (api *API) proxyBasicConvertReqBody(pbPkg *Package, packageMap map[string]*Package) string {
	if itemMap, ok := mskuConvertToPbReqCodeMap[api.Module()]; ok {
		code := itemMap[api.convertToPbReqSignMethod()]
		if len(code) > 0 {
			return code
		}
	}

	var bodyStr []string
	head := api.convertToPbReqSign()

	var params []string
	_, preDefLines := api.genPreItemLines(packageMap)
	params = append(params, preDefLines...)

	params = append(params, fmt.Sprintf("req:=&%s{", api.apiPbReqType()))
	for _, field := range api.ReqFields {
		if field.Type == "context.Context" {
			continue
		}

		item := field.toAssignPbItemVar(api, pbPkg)
		params = append(params, item)
	}
	params = append(params, "}")

	bodyStr = append(bodyStr, head)
	bodyStr = append(bodyStr, params...)
	bodyStr = append(bodyStr, "return req,nil\n}")

	return joinLn(bodyStr)
}

func joinLn(lines []string) string {
	return strings.Join(lines, "\n")
}
func ContainStr(s, s2 string) bool {
	return strings.Contains(s, s2)
}
func (api *API) proxyBasicConvertRespBody(pbPkg *Package, packageMap map[string]*Package) string {
	if itemMap, ok := mskuConvertToPbReqCodeMap[api.Module()]; ok {
		code := itemMap[api.convertToPbRespSignMethod()]
		if len(code) > 0 {
			return code
		}
	}

	head := api.toPbRespSign()
	if api.Method == "GetSkuIsBulKyTypeByWhsIdAndSkuId" {
		return head + "return constant.SkuSizeType(resp.GetRet1()), nil\n}"
	}

	var resps []string
	bodyStr := []string{}

	retItems := api.apiRetDefs()

	bodyStr = append(bodyStr, retItems...)

	bodyStr = append(bodyStr, resps...)

	method := api.genBasicAPIMethod()
	method = upFirstChar(strings.ToLower(method))

	copyLine := "if jsErr := copier.Copy(%s,%s);jsErr!=nil{"

	retLines := api.assignReturnAssignConvert(copyLine)
	bodyStr = append(bodyStr, retLines...)

	if len(api.Resp) == 1 && api.Resp[0] != "*wmserror.WMSError" {
		if api.RespItems[0].IsNormalType() {
			return head + "return resp.GetRet1()}"
		}
	}
	returnVal := "\t\treturn  err"
	if len(api.apiRets()) > 1 {
		errMsg := "\t\treturn  %s, err"
		returnVal = fmt.Sprintf(errMsg, strings.Join(api.apiRets()[0:len(api.apiRets())-1], ","))
	}

	bodyStr = append(bodyStr, returnVal)

	body := strings.Join(bodyStr, "\n")
	curBody := head + "\n" + body + "\n}"

	return curBody
}
func (api *API) proxyBasicFuncBodyWithConveted(pbPkg *Package, packageMap map[string]*Package) string {

	//module := api.Pkg.name
	var bodyStr []string

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var err *wmserror.WMSError

	method := api.genBasicAPIMethod()
	method = upFirstChar(strings.ToLower(method))
	bodyStr = append(bodyStr, "")

	var params []string
	params = append(params, fmt.Sprintf("req,err:=to%sPbReq(%s)", api.Method, api.methodReqAliasWithoutCtx(false)))
	params = append(params, "if err!=nil{")
	params = append(params, api.genNormalErrLines()...)

	var resps []string
	resps = append(resps, fmt.Sprintf("resp:=&%s{}", api.apiPbRespType()))

	bodyStr = append(bodyStr, params...)
	bodyStr = append(bodyStr, resps...)

	bodyStr = append(bodyStr, fmt.Sprintf("\t_, err = m.Client.%s(ctx, %s, req, resp, DefaultTimeOut)", method, api.endpointEnum()))

	bodyStr = append(bodyStr, "\tif err != nil {")
	bodyStr = append(bodyStr, api.genNormalErrLines()...)

	if api.isNeedViewConvertResp() {
		bodyStr = append(bodyStr, fmt.Sprintf("return parse%sPbResp(resp)", api.Method))
	} else {
		bodyStr = append(bodyStr, "return nil")
	}

	bodyStr = append(bodyStr, "\t}")
	return strings.Join(bodyStr, "\n")
}

func (api *API) assignReturnAssign(isDefineJsErr bool, copyLine string) []string {
	var bodyStr []string
	var respAssgins []string
	if len(api.apiRets()) > 0 {
		for i, ret := range api.Resp {
			if ret == "*wmserror.WMSError" {
				continue
			}
			retIdex := i + 1
			curRet := fmt.Sprintf("ret%d", retIdex)
			respRet := fmt.Sprintf("resp.GetRet%d()", retIdex)
			rawRespRet := fmt.Sprintf("resp.Ret%d", retIdex)
			if isNormalType(ret) {
				assign := fmt.Sprintf("%s = %s", curRet, respRet)
				respAssgins = append(respAssgins, assign)
			} else {
				if isDefineJsErr {
					copyLine = strings.ReplaceAll(copyLine, ":", "")
				} else {
					isDefineJsErr = true
				}

				respAssgins = append(respAssgins, fmt.Sprintf("if %s !=nil{", rawRespRet))
				respAssgins = append(respAssgins, fmt.Sprintf(copyLine, respRet, "&"+curRet))
				errLines := dealCopyErrLines(api.apiRets())

				respAssgins = append(respAssgins, errLines...)
				respAssgins = append(respAssgins, "}")
				respAssgins = append(respAssgins, "}")
			}
		}
	}
	bodyStr = append(bodyStr, "")
	if len(api.apiRets()) > 1 {
		bodyStr = append(bodyStr, "// 转换返回值")
	}

	bodyStr = append(bodyStr, respAssgins...)
	return bodyStr
}

func (api *API) assignReturnAssignConvert(copyLine string) []string {
	var bodyStr []string
	var respAssgins []string
	if len(api.apiRets()) > 0 {
		for i, ret := range api.Resp {
			if ret == "*wmserror.WMSError" {
				continue
			}
			retIdex := i + 1
			curRet := fmt.Sprintf("ret%d", retIdex)
			respRet := fmt.Sprintf("resp.GetRet%d()", retIdex)
			//rawRespRet := fmt.Sprintf("resp.Ret%d", retIdex)
			respField := api.RespItems[i]
			if respField.IsNormalType() {
				var assign string
				if ContainStr(ret, "*") {
					assign = fmt.Sprintf("%s = resp.Ret%d", curRet, retIdex)
				} else {
					assign = fmt.Sprintf("%s = %s", curRet, respRet)
				}
				respAssgins = append(respAssgins, assign)
			} else {
				if respField.isItemSlice() {
					respAssgins = append(respAssgins, fmt.Sprintf("if len(resp.Ret%d)>0{", retIdex))
				} else {
					respAssgins = append(respAssgins, fmt.Sprintf("if resp.Ret%d!=nil{", retIdex))
				}
				respAssgins = append(respAssgins, fmt.Sprintf(copyLine, respRet, "&"+curRet))
				errLines := dealCopyErrLines(api.apiRets())

				respAssgins = append(respAssgins, errLines...)
				respAssgins = append(respAssgins, "}")
				respAssgins = append(respAssgins, "}")
			}
		}
	}
	bodyStr = append(bodyStr, "")
	if len(api.apiRets()) > 1 {
		bodyStr = append(bodyStr, "// 转换返回值")
	}

	bodyStr = append(bodyStr, respAssgins...)
	return bodyStr
}

func (api *API) genNormalErrLines() []string {
	bodyStr := []string{}
	if len(api.apiRets()) > 1 {
		errMsg := "\t\treturn  %s, err.Mark()"
		rets := []string{}
		for _, retType := range api.Resp {
			if retType == "*wmserror.WMSError" {
				continue
			}
			val := getDefaultVal(retType)
			rets = append(rets, val)
		}

		bodyStr = append(bodyStr, fmt.Sprintf(errMsg, strings.Join(rets, ",")))
	} else {
		bodyStr = append(bodyStr, "return err.Mark()")
	}
	bodyStr = append(bodyStr, "\t}")
	return bodyStr
}

func getDefaultVal(retType string) string {
	switch retType {
	case "int64":
		return "0"
	case "string":
		return `""`
	case "bool":
		return `false`
	case "constant.SkuSizeType":
		return `0`
	}
	if strings.Contains(retType, "[]") {
		return "nil"
	}
	if strings.Contains(retType, "map[") {
		return "nil"
	}
	if strings.HasPrefix(retType, "*") {
		return "nil"
	}
	return retType + "{}"
}
func (api *API) genCpErrLines() []string {
	bodyStr := []string{}
	if len(api.apiRets()) > 1 {
		errMsg := "\t\treturn  %s, cpErr.Mark()"
		bodyStr = append(bodyStr, fmt.Sprintf(errMsg, strings.Join(api.apiRets()[0:len(api.apiRets())-1], ",")))
	} else {
		bodyStr = append(bodyStr, "return cpErr.Mark()")
	}
	bodyStr = append(bodyStr, "\t}")
	return bodyStr
}

//如：whsId对应pb可能是：WhsID
func (api *API) parsePbFieldType(pbPkg *Package, field *ReqField) string {
	fieldType := strings.ToLower(field.Alias)
	pbType := upFirstChar(field.Alias)
	if api.parsePbReqType(pbPkg)[fieldType] != nil {
		pbType = api.parsePbReqType(pbPkg)[fieldType].name
	}

	if pbType == "Size" && api.apiPbReqType() == "pbmsizetype.CreateSkuWeightTypeRequest" {
		pbType = "Item"
	}
	return pbType
}

func (api *API) genBasicToWMSV2PreItemDefLines(pbPkg *Package, packageMap map[string]*Package) (bool, []string) {
	module := api.Pkg.name
	isDefineJsErr := false
	params := []string{}
	for _, field := range api.ReqFields {
		if field.isContext() {
			continue
		}

		if field.isUpdateMap() {
			var lines []string
			lines = api.convertToUpdateMapLine(field)
			params = append(params, lines...)
			continue
		}

		if strings.Contains(toPbType(field.Type, packageMap), "Item") && field.Type != "*paginator.PageIn" {
			lines := []string{}
			initLines := field.VarItem(false, api)
			lines = append(lines, initLines...)

			upAlias := upFirstChar(field.formatFieldAlias())
			//兼容MsizetypeCreateTaskSizeType
			if field.Alias == "size" {
				upAlias = "Item"
			}
			if field.Alias == "entity" {
				upAlias = "Entity"
			}
			lines = append(lines, fmt.Sprintf("if req.%s != nil {", upAlias))
			origItem := field.toDefBasicItemOrItems(module)
			lines = append(lines, origItem...)
			errMsg := "\t\tif jsErr := copier.Copy(req.%s, &%s); jsErr != nil {\n"
			errMsg += api.viewHandlerJsErr()

			if field.isPointer() {
				errMsg = strings.ReplaceAll(errMsg, "&", "")
			}

			lines = append(lines, fmt.Sprintf(errMsg, upAlias, field.formatFieldAlias()))

			lines = append(lines, "}")

			//lines = append(lines, api.viewHandlerErr())
			params = append(params, lines...)
		}

		//*paginator.PageIn
		if field.isPageInItem() {
			lines := field.convertPbToBasic(module)
			params = append(params, lines...)
		}

		if isNormalType(field.Type) {
			var item string
			//if field.Alias == "whsID" {
			//	item = fmt.Sprintf("var \t%s =req.GetWhsId()", field.aliasDef())
			//} else {

			pbType := api.parsePbFieldType(pbPkg, field)
			item = fmt.Sprintf("var \t%s =req.Get%s()", field.aliasDef(), pbType)
			//}
			params = append(params, item)
		}

		if strings.Contains(field.Type, "constant.") {
			var item string
			if strings.Contains(field.Type, "[]") {
				params = append(params, "%s:=req.Get%s")
				item = fmt.Sprintf("var \t%s = %s", field.aliasDef(), upFirstChar(field.Alias))
			} else {
				item = fmt.Sprintf("var \t%s =req.Get%s()", field.Alias, upFirstChar(field.Alias))
			}
			params = append(params, item)
		}

	}
	return isDefineJsErr, params
}

func (api *API) genWmsV2ToBasicPreItemDefLines(packageMap map[string]*Package) (bool, []string) {
	module := api.Pkg.name
	isDefineJsErr := false
	params := []string{}
	for _, field := range api.ReqFields {
		if field.isContext() {
			continue
		}

		if field.isUpdateMap() {
			var lines []string
			lines = api.convertToMapUpdateItemsLine(field)
			params = append(params, lines...)
			continue
		}

		if strings.Contains(toPbType(field.Type, packageMap), "Item") && field.Type != "*paginator.PageIn" {
			lines := field.toPbDefItemOrItems(module)

			errLines := field.genDealCopyJsErrLines(&isDefineJsErr, *api)
			lines = append(lines, errLines...)
			params = append(params, lines...)
		}

		//兼容 constant枚举值
		//sizeTypeList []constant.TaskSizeType
		if strings.Contains(field.Type, "[]") && strings.Contains(field.Type, "constant.") {
			lines := field.toPbDefItemOrItems(module)

			errLines := field.genDealCopyJsErrLines(&isDefineJsErr, *api)
			lines = append(lines, errLines...)
			params = append(params, lines...)
		}

		//*paginator.PageIn
		if field.isPageInItem() {
			lines := field.convertPageInAssignLines(module)
			params = append(params, lines...)
		}

	}
	return isDefineJsErr, params
}

func (api *API) genPreItemLines(packageMap map[string]*Package) (bool, []string) {
	module := api.Pkg.name
	isDefineJsErr := false
	params := []string{}
	for _, field := range api.ReqFields {
		if field.isContext() {
			continue
		}
		if !field.isSpec() {
			continue
		}

		if field.isPageInItem() {
			lines := field.convertPageInAssignLines(module)
			params = append(params, lines...)
			continue
		}

		if field.isUpdateMap() {
			var lines []string
			//lines = api.convertToMapUpdateItemsLineWithConvert(field)
			lines = field.wmsbasicUpdateMapToPbItemLines(api)

			params = append(params, lines...)
			continue
		}

		if strings.Contains(toPbType(field.Type, packageMap), "Item") && field.Type != "*paginator.PageIn" {
			//lines := field.toPbDefItemOrItems(module)
			lines, errLines := api.wmsbasicItemToPbItems(field)
			lines = append(lines, errLines...)
			params = append(params, lines...)
			continue
		}

		//兼容 constant枚举值
		//sizeTypeList []constant.TaskSizeType
		if strings.Contains(field.Type, "[]") && strings.Contains(field.Type, "constant.") {
			lines := field.toPbDefItemOrItems(module)

			errLines := field.genDealCopyJsErrLinesWithConvert(*api)
			lines = append(lines, errLines...)
			params = append(params, lines...)
			continue
		}
		if !strings.Contains(field.Type, "[]") && strings.Contains(field.Type, "constant.") {
			continue
		}

		//*paginator.PageIn
		params = append(params, "panic(1):", field.Type)
		continue

	}
	return isDefineJsErr, params
}

func (api *API) wmsbasicItemToPbItems(field *ReqField) ([]string, []string) {
	lines := field.VarPbItem(false, api)

	errLines := field.genDealCopyJsErrLinesWithConvert(*api)
	return lines, errLines
}

func (api *API) convertToMapUpdateItemsLine(field *ReqField) []string {
	module := api.Pkg.name
	var params []string
	//if module != "msizetype" {
	retItemVars := api.apiRets()
	params = append(params, fmt.Sprintf("mapItems,err := convertToMapUpdateItems(%s)", field.Alias))

	params = append(params, "if err != nil {")
	if len(retItemVars) > 1 {
		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())"
		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))
	} else {
		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())")
	}
	params = append(params, "}")
	params = append(params, fmt.Sprintf("mapItemLists := []*pb%s.MapItem{}", module))
	params = append(params, "cpErr := copier.Copy(mapItems, &mapItemLists)")
	params = append(params, "if cpErr != nil {")
	if len(retItemVars) > 1 {
		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", cpErr.Error())"
		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))
	} else {
		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", cpErr.Error())")
	}

	params = append(params, "}")
	//} else {
	//
	//	retItemVars := api.apiRets()
	//	params = append(params, fmt.Sprintf("mapItemLists,err := convertToMapUpdateItems(%s)", field.Alias))
	//
	//	params = append(params, "if err != nil {")
	//	if len(retItemVars) > 1 {
	//		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())"
	//		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))
	//	} else {
	//		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())")
	//	}
	//	params = append(params, "}")
	//}
	return params
}

func (api *API) convertToMapUpdateItemsLineWithConvert(field *ReqField) []string {
	module := api.Pkg.name
	var params []string
	params = append(params, fmt.Sprintf("mapItems,err := convertToMapUpdateItems(%s)", field.Alias))

	params = append(params, "if err != nil {")
	params = append(params, "\t\treturn  nil,wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())")
	params = append(params, "}")
	params = append(params, fmt.Sprintf("mapItemLists := []*pb%s.MapItem{}", module))
	params = append(params, "cpErr := copier.Copy(mapItems, &mapItemLists)")
	params = append(params, "if cpErr != nil {")
	params = append(params, "\t\treturn  nil,wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", cpErr.Error())")
	params = append(params, "}")

	return params
}

func (api *API) convertToUpdateMapLine(field *ReqField) []string {
	var params []string
	//兼容非updateMap
	params = append(params, fmt.Sprintf("%s,err := pbconvert.ConvertUpdateMaps(req.Get%s())", field.Alias, upFirstChar(field.Alias)))
	params = append(params, api.viewHandlerErr())
	api.genBasicV2Err = true
	return params
}

func (api *API) apiPbReqType() string {
	module := api.Pkg.name
	return fmt.Sprintf("pb%s.%sRequest", module, api.Method)
}
func (api *API) apiPbRespType() string {
	module := api.Pkg.name
	return fmt.Sprintf("pb%s.%sResponse", module, api.Method)
}

func (api *API) endpointEnum() string {
	endPointEnum := upFirstChar(api.Pkg.name) + api.Method
	return endPointEnum
}

func dealCopyErrLines(retItemVars []string) []string {
	var params []string
	if len(retItemVars) > 1 {
		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())"
		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))

	} else {
		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())")
	}
	return params
}

func dealCopyErrLinesWithConvert(retItemVars []string) []string {
	var params []string

	params = append(params, "\t\treturn  nil,wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())")
	params = append(params, "}")
	return params
}

func isNormalType(fieldTypeStr string) bool {
	normalTypes := []string{
		"bool",
		"*bool",
		"int64",
		"uint64",
		"*int64",
		"int",
		"string",
		"*string",
		"[]string",
		"[]int64",
	}
	for _, normalType := range normalTypes {
		if normalType == fieldTypeStr {
			return true
		}
	}
	return false
}

func (api *API) parsePbType(pbPkg *Package, pbReqType string, itemTypeMap map[string]map[string]*Field) {
	if pbPkg != nil {
		pbItemType, err := pbPkg.FindType(pbReqType)
		if err != nil {
			println(err.Error())
		}
		keyToMap := map[string]*Field{}
		if objType, ok := pbItemType.def.(*StructType); ok {
			for _, field := range objType.fields {
				keyToMap[strings.ToLower(field.name)] = field
			}
		}
		itemTypeMap[pbReqType] = keyToMap
	}
}

// eg [ret1,ret2,err]
func (api *API) apiRets() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("ret%d", i+1)
		if ret == "*wmserror.WMSError" {
			v = "err"
		}
		rets = append(rets, v)
	}
	return rets
}

func (api *API) apiProxyRets() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("proxyRet%d", i+1)
		if ret == "*wmserror.WMSError" {
			v = "err"
		}
		rets = append(rets, v)
	}
	return rets
}

func (api *API) apiRetsWithProxyTmp() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("proxyRet%d", i+1)
		if isInPkgSturctItem(ret) {
			v = "tmp" + upFirstChar(v)
		}
		if ret == "*wmserror.WMSError" {
			v = "proxyErr"
		}
		rets = append(rets, v)
	}
	return rets
}

func (api *API) apiPbRets() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("ret%d", i+1)
		v = convertToPbType(ret, v)
		if ret == "*wmserror.WMSError" {
			v = "err"
		}
		rets = append(rets, v)
	}
	return rets
}

// eg [
//	 "var ret1 int64",
//	 "var err *wmserr.err",
//]
func (api *API) apiRetDefs() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("var %s  %s", fmt.Sprintf("ret%d", i+1), ret)
		if ret == "*wmserror.WMSError" {
			v = "var err *wmserror.WMSError"
		} else {
			if !isNormalType(ret) {
				if isSturctItems(ret) {
					v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), api.convertToBasicDtoType(ret))
				} else {
					if strings.Contains(ret, "map[") {
						v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), ret)
					} else {
						ret = strings.ReplaceAll(ret, "*", "&")
						v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), api.convertToBasicDtoType(ret))
					}
				}
			}
		}

		rets = append(rets, v)
	}
	return rets
}

func (api *API) apiRetDefsSrcProxyWithoutConvertToDto() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("var %s  %s", fmt.Sprintf("ret%d", i+1), ret)
		if ret == "*wmserror.WMSError" {
			v = "var err *wmserror.WMSError"
		} else if ret == "constant.SkuSizeType" {
			v = fmt.Sprintf("var %s  %s", fmt.Sprintf("ret%d", i+1), ret)
		} else {
			if !isNormalType(ret) {
				if isSturctItems(ret) {
					v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), ret)
				} else {
					if strings.HasPrefix(ret, "map[") {
						v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), ret)
					} else {
						ret = strings.ReplaceAll(ret, "*", "&")
						v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), ret)
					}
				}
			}
		}

		rets = append(rets, v)
	}
	return rets
}

func (api *API) proxyFuncBody2() string {
	if itemMap, ok := srcProxyCodeMap[api.Module()]; ok {
		code := itemMap[api.Method]
		if len(code) > 0 {
			return code
		}
	}
	var bodyStr []string
	bodyStr = append(bodyStr, api.FuncSignStr+"{")

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var ret3 *wmserror.WMSError
	//for i, ret := range api.Resp {
	//	v := fmt.Sprintf("var %s %s", fmt.Sprintf("ret%d", i), ret)
	//	bodyStr = append(bodyStr, v)
	//}
	bodyStr = append(bodyStr, api.apiRetDefsSrcProxyWithoutConvertToDto()...)

	//
	//originHandler := func(ctx context.Context) {
	//	ret1, ret2, ret3 = c.origin.SearchCellSizeList(ctx, whsID)
	//}
	rets := strings.Join(api.apiRets(), ", ")

	bodyStr = append(bodyStr, "\toriginHandler := func(ctx context.Context) {")
	params := []string{}
	for _, field := range api.ReqFields {
		if field.Alias == "isUseReplica" && field.Type == "bool" {
			params = append(params, field.Alias+"...")
		} else if field.Alias == "options" && field.Type == "db_config.Option" {
			params = append(params, field.Alias+"...")
		} else {
			params = append(params, field.Alias)
		}
	}
	paramsStr := strings.Join(params, ", ")

	callOriginal := fmt.Sprintf("= %s.%s.%s(%s)", api.ReceiverAlias, lowerFirstChar(api.ReceiverName), api.Method, paramsStr)
	bodyStr = append(bodyStr, rets+callOriginal)
	bodyStr = append(bodyStr, "\t}")

	bodyStr = append(bodyStr, "\tproxyHandler := func(ctx context.Context) *wmserror.WMSError{")
	proxyParams := []string{}
	for _, field := range api.ReqFields {
		if field.Alias == "isUseReplica" && field.Type == "bool" {
			proxyParams = append(proxyParams, fmt.Sprintf("len(%s)>0", field.Alias))
			continue
		}
		if field.Alias == "options" && field.Type == "db_config.Option" {
			bodyStr = append(bodyStr, "\t\toptionItem := &wmsbasic.DbOption{UseMaster: db_config.GetConfig(options).IsUseMaster()}")
			proxyParams = append(proxyParams, "optionItem")
			continue
		}
		if api.isNeedRedefineStruct(field) {
			copyReqs := []string{}

			reqStr := fmt.Sprintf("%sReq", field.Alias)
			//req := &wmsbasic.SearchCellSizeConditionItem{}
			originType := field.Type
			reqItemType := field.Type
			if strings.Contains(reqItemType, "*") && !strings.Contains(reqItemType, "[") {
				reqItemType = strings.Split(reqItemType, "*")[1]
			}
			if isSturctItems(originType) {
				fType := strings.ReplaceAll(originType, "[]*", "")
				copyReqs = append(copyReqs, fmt.Sprintf("%s := []*wmsbasic.%sItem{}", reqStr, fType))
			} else {
				if strings.Contains(field.Type, "*") {
					copyReqs = append(copyReqs, fmt.Sprintf("%s := &wmsbasic.%sItem{}", reqStr, reqItemType))
				} else {
					copyReqs = append(copyReqs, fmt.Sprintf("%s := wmsbasic.%sItem{}", reqStr, reqItemType))
				}
			}

			//ctErr := copier.Copy(condition, &req)
			copyReqs = append(copyReqs, fmt.Sprintf("ctErr := copier.Copy(%s, %s)", field.Alias, reqStr))
			//if ctErr != nil {
			//	return wmserror.NewError(constant.ErrJsonDecodeFail, ctErr.Error())
			//}
			copyReqs = append(copyReqs, "if ctErr != nil {")
			copyReqs = append(copyReqs, "return wmserror.NewError(constant.ErrJsonDecodeFail, ctErr.Error())")
			copyReqs = append(copyReqs, "}")

			bodyStr = append(bodyStr, strings.Join(copyReqs, "\n"))
			proxyParams = append(proxyParams, reqStr)
		} else {
			proxyParams = append(proxyParams, field.Alias)
		}
	}
	proxyParamsStr := strings.Join(proxyParams, ", ")

	proxyCallOriginal := fmt.Sprintf(":= %s.%sProxyAPI.%s(%s)", api.ReceiverAlias, lowerFirstChar(api.ReceiverName), api.Method, proxyParamsStr)
	//处理返回值为当前包下的struct
	bodyStr = append(bodyStr, strings.Join(api.apiRetsWithProxyTmp(), ",")+proxyCallOriginal)
	bodyStr = append(bodyStr, "err = proxyErr")
	bodyStr = append(bodyStr, "if proxyErr!=nil{\n return proxyErr.Mark() \n}")

	lines := api.genCopyTmpVar()
	bodyStr = append(bodyStr, lines...)

	bodyStr = append(bodyStr, "return nil")
	bodyStr = append(bodyStr, "\t}")

	bodyStr = append(bodyStr, fmt.Sprintf("endPoint := \"%s\"", api.Method))
	if api.genBasicAPIMethod() == "GET" {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler, apiIdempotent)")
	} else {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler)")
	}
	bodyStr = append(bodyStr, "return "+rets)
	bodyStr = append(bodyStr, "}")

	return strings.Join(bodyStr, "\n")
}
func (api *API) proxyPbAPIReq() string {
	basicAPI := &BASICAPI{
		Package:     "",
		Req:         nil,
		ReqFields:   nil,
		RespTypeStr: nil,
		Pkg:         nil,
	}

	basicAPI.Method = api.genBasicAPIMethod()
	basicAPI.Path = "openapi/basicv2/" + api.Path + "/" + api.Method
	var reqFieldStr []string
	reqFieldStr = append(reqFieldStr, fmt.Sprintf("type %s%sReq struct{", upFirstChar(api.Package), api.Method))

	innerStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldParam := field.Alias
		fieldParamDef := upFirstChar(fieldParam)
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		//if !strings.Contains(fieldType, ".") &&
		//	fieldType != "string" &&
		//	fieldType != "int64" &&
		//	fieldType != "[]string" &&
		//	fieldType != "[]int64" {
		if api.isNeedRedefineStruct(field) {

			innerStructset.Add(strings.ReplaceAll(fieldType, "*", ""))
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %sItem `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		} else {
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %s `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		}
	}

	reqFieldStr = append(reqFieldStr, "}")
	for _, i := range innerStructset.Values() {
		fieldType := i.(string)
		depStructFieldType := api.genInnerPkgStructDef(fieldType)

		reqFieldStr = append(reqFieldStr, depStructFieldType)
	}

	reqDef := strings.Join(reqFieldStr, "\n")
	ret := reqDef
	return ret

}

func (api *API) proxyPbAPI() *BASICAPI {
	basicAPI := &BASICAPI{
		Package:     "",
		Req:         nil,
		ReqFields:   nil,
		RespTypeStr: nil,
		Pkg:         nil,
		api:         *api,
	}

	basicAPI.Package = api.Package
	basicAPI.Method = api.genBasicAPIMethod()
	basicAPI.Path = "openapi/basicv2/" + api.Path + "/" + api.Method
	basicAPI.ReqFields = api.ReqFields
	basicAPI.RespTypeStr = api.Resp
	return basicAPI

}

func (api *API) proxyProxyAPIReqItem() []string {
	basicAPI := &BASICAPI{}

	basicAPI.Path = "openapi/basicv2/" + api.Path + "/" + api.Method
	var reqFieldStr []string
	reqFieldStr = append(reqFieldStr, fmt.Sprintf("type %s%sReq struct{", upFirstChar(api.Package), api.Method))

	for _, field := range api.ReqFields {
		fieldParam := field.Alias
		fieldParamDef := upFirstChar(fieldParam)
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		//if !strings.Contains(fieldType, ".") &&
		//	fieldType != "string" &&
		//	fieldType != "int64" &&
		//	fieldType != "[]string" &&
		//	fieldType != "[]int64" {
		if api.isNeedRedefineStruct(field) {
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %sItem `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		} else {
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %s `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		}
	}

	reqFieldStr = append(reqFieldStr, "}")
	var itemFields []string
	for _, i := range api.genInnerDefPkgStructs() {
		ftype := i
		if isNormalType(ftype) || strings.Contains(ftype, ".") {
			continue
		}
		if !api.isNeedRedefineStructByType(i) {
			continue
		}

		fieldType := i
		depStructFieldType := api.genInnerPkgStructDef(fieldType)

		itemFields = append(itemFields, depStructFieldType)
	}

	return itemFields

}

func (api *API) BasicAPIInterfaceSignWithComment() string {
	//prefix := "// proxy 原来 msku.SKUManager GetSkuSetForHighValueByWhsID 的请求\n "
	prefix := fmt.Sprintf("// %s \n// proxy 原来 %s.%s %s 的请求\n ", api.Method, api.Package, api.ReceiverName, api.Method)
	//println(prefix)
	sign := api.proxyBasicSign()
	return prefix + sign
}

func (api *API) proxyBasicSign() string {
	sign := fmt.Sprintf("%s(%s) %s", api.Method, api.methodReqSign(), api.methodReturnSign())
	return sign
}

func (api *API) methodReturnSign() string {
	var retParams []string
	for i := range api.Resp {
		retType := api.Resp[i]
		if api.isNeedRedefineStructByType(retType) {
			retType = api.convertToBasicDtoType(retType)
		}
		if retType == "map[SupplierIDType]SupplierNameType" {
			retType = "map[int64]string"
		}

		retParams = append(retParams, fmt.Sprintf("%s ", retType))
	}
	var retSign = ""
	if len(retParams) > 1 {
		retSign = fmt.Sprintf("(%s)", strings.Join(retParams, ", "))
	} else {
		retSign = retParams[0]
	}
	return retSign
}
func (api *API) genInnerDefPkgStructs() []string {
	innerStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		if isNormalType(fieldType) {
			continue
		}

		//外部类型
		if field.isContainOutStruct() {
			continue
		}

		item := strings.ReplaceAll(fieldType, "*", "")
		item = strings.ReplaceAll(item, "[]", "")
		innerStructset.Add(item)
		//解析请求参数中 包含内部/外部的struct
		for _, s := range api.parseInStructs(item) {
			innerStructset.Add(s)
		}
	}
	if api.Pkg.name == "mlifecyclerule" {
		innerStructset.Add("ConfirmRuleItem")
	}
	for _, retType := range api.Resp {
		if isNormalType(retType) {
			continue
		}
		if strings.Contains(retType, ".") {
			continue
		}
		item := strings.ReplaceAll(retType, "*", "")
		item = strings.ReplaceAll(item, "[]", "")
		innerStructset.Add(item)
		//解析请求参数中 包含内部/外部的struct
		for _, s := range api.parseInStructs(item) {
			innerStructset.Add(s)
		}

	}
	var items []string
	for _, i := range innerStructset.Values() {
		fieldType := i.(string)
		items = append(items, fieldType)
	}

	return uniqSlice(items...)
}
func (api *API) genOuterDefPkgStructs() []string {
	outStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		fieldType = strings.ReplaceAll(fieldType, "*", "")
		//当前包下的struct
		if strings.Contains(fieldType, ".") {
			outStructset.Add(fieldType)
		}
		for _, s := range api.parseOutStructs(fieldType) {
			outStructset.Add(s)
		}
	}
	for _, field := range api.Resp {
		//当前包下的struct
		if strings.Contains(field, ".") {
			outStructset.Add(field)
		}
		//field = strings.ReplaceAll(field, "map[string][]*", "")
		field = strings.ReplaceAll(field, "*", "")

		for _, s := range api.parseOutStructs(field) {
			outStructset.Add(s)
		}
	}
	var items []string
	for _, i := range outStructset.Values() {
		fieldType := i.(string)
		items = append(items, fieldType)
	}
	return items
}
func (api *API) genInnerPkgStructDef(fieldType string) string {
	//兼容[]*sss
	fieldType = strings.ReplaceAll(fieldType, "[]", "")
	var def = []string{}
	defHead := fmt.Sprintf("type %sItem struct{", fieldType)
	def = append(def, defHead)
	for _, file := range api.Pkg.files {
		t, err := file.FindType(fieldType)
		if err != nil && strings.Contains(err.Error(), "is not found") {
			continue
		}
		//for _, field := range t.def.(*StructType).Fields() {
		//	println(field.Definition().String())
		//}
		originDef := t.Definition().String()
		if api.Pkg.name == "msku" {
			if fieldType == "CategoryTreeNod" {
				originDef = strings.ReplaceAll(originDef, "[]*CategoryTreeNode", "[]*CategoryTreeNodeItem")
			}
			if fieldType == "LoopUpdateCategoryRegionAttr" {
				originDef = strings.ReplaceAll(originDef, "[]*BatchUpdateCategories", "[]*BatchUpdateCategoriesItem")
			}
			if fieldType == "LoopUpdateCategoryWhsAttr" {
				originDef = strings.ReplaceAll(originDef, "[]*BatchUpdateCategoriesWhsAttr", "[]*BatchUpdateCategoriesWhsAttrItem")
			}
			if fieldType == "ExportShopCondition" {
				originDef = strings.ReplaceAll(originDef, "ExportShopCondition", "ExportShopConditionItem")
			}
			if fieldType == "CategoryTreeNode" {
				originDef = strings.ReplaceAll(originDef, "[]*CategoryTreeNode", "[]*CategoryTreeNodeItem")
			}
			if fieldType == "ExportShopCondition" {
				originDef = strings.ReplaceAll(originDef, "ExportShopIdOneOfCondition", "ExportShopIdOneOfConditionItem")
			}
		}

		withoutHeadDef := strings.ReplaceAll(originDef, "struct {", "")
		def = append(def, withoutHeadDef)
		//println(t)
	}
	return strings.Join(def, "\n")
}

func (api *API) methodReqSign() string {
	var params []string
	for _, field := range api.ReqFields {
		curFieldType := field.Type
		if api.isNeedRedefineStruct(field) {
			curFieldType = curFieldType + "Item"
		}
		if field.Type == "*pbshop.ExportShopRequest" {
			curFieldType = "ExportShopRequestItem"
		}
		if field.Type == "db_config.Option" {
			curFieldType = "*DbOption"
		}
		//兼容type []HighValueCategoryUpdateConditionItem
		//curFieldType = strings.ReplaceAll(curFieldType, "[]", "")
		params = append(params, fmt.Sprintf("%s %s", field.Alias, curFieldType))
	}
	return strings.Join(params, ",")
}

func (api *API) methodReqAliasWithoutCtx(isNeedType bool) string {
	var params []string
	for _, field := range api.ReqFields {
		curFieldType := field.Type
		if field.isContext() {
			continue
		}
		if api.isNeedRedefineStruct(field) {
			curFieldType = curFieldType + "Item"
		}
		if field.Type == "*pbshop.ExportShopRequest" {
			curFieldType = "ExportShopRequestItem"
		}
		//兼容type []HighValueCategoryUpdateConditionItem
		//curFieldType = strings.ReplaceAll(curFieldType, "[]", "")
		if isNeedType {
			params = append(params, fmt.Sprintf("%s %s", field.Alias, curFieldType))
		} else {
			params = append(params, fmt.Sprintf("%s", field.Alias))
		}
	}
	return strings.Join(params, ",")
}

func (api *API) methodRespAliasWithoutErr(isNeedType bool) string {
	var params []string
	for _, field := range api.RespItems {
		curFieldType := field.Type
		if field.Type == "*wmserror.WMSError" {
			continue
		}
		//if api.isNeedRedefineStruct(field) {
		//	curFieldType = curFieldType + "Item"
		//}
		//兼容type []HighValueCategoryUpdateConditionItem
		//curFieldType = strings.ReplaceAll(curFieldType, "[]", "")

		objType := field.ObjType()
		if !ContainStr(objType, ".") && !ContainStr(objType, "map[") && !isNormalType(objType) {
			curType := strings.ReplaceAll(field.Type, objType, fmt.Sprintf("%s.%s", api.Module(), objType))
			curFieldType = curType
		}

		if isNeedType {
			params = append(params, fmt.Sprintf("%s %s", field.Alias, curFieldType))
		} else {
			params = append(params, fmt.Sprintf("%s", field.Alias))
		}

	}
	return strings.Join(params, ",")
}

func (api *API) isNeedRedefineStruct(field *ReqField) bool {
	fType := strings.ReplaceAll(field.Type, "[]", "")

	return api.isNeedRedefineStructByType(fType)
}

func (api *API) isNeedRedefineStructByType(fType string) bool {
	fType = strings.ReplaceAll(fType, "*", "")
	return !strings.Contains(fType, ".") &&
		!strings.Contains(fType, "map[string]") &&
		!strings.Contains(fType, "map[int64]") &&
		!strings.Contains(fType, "map[uint64]") &&
		!strings.Contains(fType, "map[SupplierIDType]") &&
		fType != "context.Context" &&
		fType != "string" &&
		fType != "bool" &&
		fType != "*bool" &&
		fType != "int64" &&
		fType != "int" &&
		fType != "uint64" &&
		fType != "*int64" &&
		fType != "[]string" &&
		fType != "[]int64"
}

func (api *API) genBasicAPIMethod() string {
	//全是POST ，但是通过业务层去控制，是不是幂等操作

	return "POST"
	//if len(api.Resp) == 1 {
	//	return "POST"
	//}
	//return "GET"
}

func (api *API) pbReqType() string {
	return fmt.Sprintf("%sRequest", api.Method)

}

// 解析pb对应的字段map，可以获取到对应的json tag
func (api *API) parsePbReqType(pbPkg *Package) map[string]*Field {
	pbReqType := api.pbReqType()
	itemTypeMap := map[string]map[string]*Field{}
	api.parsePbType(pbPkg, pbReqType, itemTypeMap)
	reqPbTypesMap := itemTypeMap[pbReqType]

	return reqPbTypesMap
}

func (api API) isNeedHandler(conf *CodeGenConf) bool {
	receiverName := api.ReceiverName
	receiverName = strings.ReplaceAll(receiverName, "*", "")
	isNeedHandler := false
	for _, targetStruct := range conf.targetStructs {
		if receiverName == targetStruct {
			isNeedHandler = true
		}
	}
	return isNeedHandler

}

func (b API) convertToBasicDtoType(retType string) string {
	if isNormalType(retType) {
		return retType
	}

	if strings.Contains(retType, ".") {
		return retType
	}
	if retType == "map[SupplierIDType]SupplierNameType" {
		return "map[int64]string"
	}

	origin := retType
	realType := strings.ReplaceAll(strings.ReplaceAll(retType, "[]", ""), "*", "")
	if !isNormalType(realType) {
		if strings.Contains(origin, "[]") {
			if strings.Contains(origin, "*") {
				return fmt.Sprintf("[]*%sItem", realType)
			} else {
				return fmt.Sprintf("[]*%sItem", realType)
			}
		} else {
			if strings.Contains(origin, "*") {
				return fmt.Sprintf("*%sItem", realType)
			} else {
				return fmt.Sprintf("%sItem", realType)
			}
		}
	}

	return retType
}

func (api API) isContainTmpVar() bool {
	for _, ret := range api.apiRetsWithProxyTmp() {
		if strings.Contains(ret, "tmp") {
			return true
		}
	}
	return false
}

func (api API) genCopyTmpVar() []string {
	lines := []string{}
	retTypes := api.Resp
	for i, ret := range api.apiRetsWithProxyTmp() {
		retType := retTypes[i]
		isErr := retType == "*wmserror.WMSError"
		if isErr {
			continue
		}
		assignRet := fmt.Sprintf("ret%d", i+1)

		if isNormalType(retType) {
			lines = append(lines, fmt.Sprintf("ret%d = proxyRet%d", i+1, i+1))
			continue
		} else {
			//切片数组列表
			if strings.Contains(ret, "tmp") {
				if strings.Contains(retType, "[]") && !strings.Contains(retType, ".") {
					lines = append(lines, fmt.Sprintf("if cpErr:=copier.Copy(%s,&%s);cpErr!=nil{", ret, assignRet))
					lines = append(lines, "return wmserror.NewError(constant.ErrJsonDecodeFail, cpErr.Error()) \n}")
				} else {
					isPointer := strings.Contains(retType, "*")

					lines = append(lines, fmt.Sprintf("if %s!=nil{", ret))
					if isPointer {
						lines = append(lines, fmt.Sprintf("if cpErr:=copier.Copy(%s,%s);cpErr!=nil{", ret, assignRet))
					} else {
						lines = append(lines, fmt.Sprintf("if cpErr:=copier.Copy(%s,&%s);cpErr!=nil{", ret, assignRet))
					}
					lines = append(lines, "return wmserror.NewError(constant.ErrJsonDecodeFail, cpErr.Error()) \n}")
					lines = append(lines, "}")
				}
			} else {
				//lines = append(lines, "xxxxx:"+ret)
				lines = append(lines, fmt.Sprintf("%s = %s", assignRet, ret))
			}
		}
	}
	return lines
}

func (b *API) parseInStructs(itemType string) []string {
	ktype, err := b.Pkg.FindType(itemType)
	if err != nil {
		return []string{}
	}
	var items []string
	if obj, ok := ktype.def.(*StructType); ok {
		for _, field := range obj.fields {
			fieldType := field.def.String()
			actualType := strings.ReplaceAll(strings.ReplaceAll(fieldType, "[]", ""), "*", "")
			if !isNormalType(fieldType) && !strings.Contains(actualType, ".") {
				println("parse inner struct type:", fieldType)
				items = append(items, actualType)
			}
		}
	}
	return items
}
func (b *API) parseOutStructs(itemType string) []string {
	var items []string
	ktype, err := b.Pkg.FindType(itemType)
	if err != nil {
		return []string{}
	}
	if obj, ok := ktype.def.(*StructType); ok {
		for _, field := range obj.fields {
			fieldType := field.def.String()
			actualType := strings.ReplaceAll(strings.ReplaceAll(fieldType, "[]", ""), "*", "")
			if !isNormalType(fieldType) && strings.Contains(actualType, ".") {
				println("parse inner def out struct type:", fieldType)
				items = append(items, actualType)
			}
		}
	}

	for packagePath, p := range b.pkgMap {
		pathSegs := strings.Split(packagePath, "/")
		pkgName := pathSegs[len(pathSegs)-1]
		if pkgName == "entity" || pkgName == "message" {
			ktype, err := p.FindType(itemType)
			if err != nil {
				return items
			}
			if obj, ok := ktype.def.(*StructType); ok {
				for _, field := range obj.fields {
					fieldType := field.def.String()
					actualType := strings.ReplaceAll(strings.ReplaceAll(fieldType, "[]", ""), "*", "")
					if !isNormalType(fieldType) {
						println("parse out struct type:", fieldType)
						items = append(items, actualType)
					}
				}
			}
		}
	}

	return items

}

func (api *API) convertToPbReqSign() string {
	return fmt.Sprintf("func to%sPbReq(%s)(*%s,*wmserror.WMSError) {", api.Method, api.methodReqAliasWithoutCtx(true), api.apiPbReqType())
}
func (api *API) helperConvertToPbRespSign() string {
	return fmt.Sprintf("func to%sPbResp(%s)(*%s,*wmserror.WMSError) {", api.Method, api.methodRespAliasWithoutErr(true), api.apiPbRespType())
}
func (api *API) helperConvertToPbRespSignMethod() string {
	return fmt.Sprintf("to%sPbResp", api.Method)
}

func (api *API) convertToPbReqSignMethod() string {
	return fmt.Sprintf("to%sPbReq", api.Method)
}

func (api *API) pbReqSign() string {
	return fmt.Sprintf("%sRequest", api.Method)
}
func (api *API) pbRespSign() string {
	return fmt.Sprintf("%sResponse", api.Method)
}
func (api *API) convertToPbRespSignMethod() string {
	return fmt.Sprintf("parse%sPbResp", api.Method)
}
func (api *API) toPbRespSign() string {
	return fmt.Sprintf("func parse%sPbResp(resp *%s) %s{", api.Method, api.apiPbRespType(), api.methodReturnSign())
}

func (b API) Module() string {
	return b.Pkg.name
}

func (b API) isNeedProxy() bool {

	if len(b.ReqFields) > 0 && !b.ReqFields[0].isContext() {
		return false
	}

	if len(b.Resp) > 0 && b.RespItems[len(b.RespItems)-1].Type != "*wmserror.WMSError" {
		return false
	}

	return true
}

func (b API) parseReqToOriginMethod() string {
	return fmt.Sprintf("parse%sPbRequest", b.Method)
}

func (api API) parseReqToOriginMethodSign() string {
	method := api.parseReqToOriginMethod()
	pbType := api.pbReqSign()
	retTypes := api.apiReqTypeWithoutCtx()
	return fmt.Sprintf("func %s(req *pb%s.%s)(%s,*wmserror.WMSError) {", method, api.Module(), pbType, strings.Join(retTypes, ","))
}

func (api API) apiReqTypeWithoutCtx() []string {
	retTypes := []string{}
	for _, field := range api.ReqFields {
		if field.isContext() {
			continue
		}
		objType := field.ObjType()
		if isNormalType(objType) {
			retTypes = append(retTypes, field.Type)
		} else {
			if ContainStr(field.Type, ".") {
				retTypes = append(retTypes, field.Type)
			} else if ContainStr(field.Type, "map[") {
				retTypes = append(retTypes, field.Type)
			} else {
				curType := strings.ReplaceAll(field.Type, objType, fmt.Sprintf("%s.%s", api.Module(), objType))
				retTypes = append(retTypes, curType)
			}

		}
	}
	return retTypes
}
func (api API) apiRespTypeWithoutCtx() []string {
	retTypes := []string{}
	for _, field := range api.RespItems {
		if field.Type == "*wmserror.WMSError" {
			continue
		}
		objType := field.ObjType()
		if isNormalType(objType) {
			retTypes = append(retTypes, field.Type)
		} else {
			if ContainStr(field.Type, ".") {
				retTypes = append(retTypes, field.Type)
			} else if ContainStr(field.Type, "map[") {
				retTypes = append(retTypes, field.Type)
			} else {
				curType := strings.ReplaceAll(field.Type, objType, fmt.Sprintf("%s.%s", api.Module(), objType))
				retTypes = append(retTypes, curType)
			}

		}
	}
	return retTypes
}

func (api API) apiReqAliasWithoutCtx() []string {
	retTypes := []string{}
	for _, field := range api.ReqFields {
		if field.isContext() {
			continue
		}
		retTypes = append(retTypes, field.Alias)
	}
	return retTypes
}

func (api API) apiReqAliasWithoutCtxDeafultVal() []string {
	retTypes := []string{}
	for _, field := range api.ReqFields {
		if field.isContext() {
			continue
		}
		retTypes = append(retTypes, getDefaultVal(field.Type))
	}
	return retTypes
}

func (b API) isNeedViewConvertReq() bool {
	return len(b.ReqFields) > 1
}
func (b API) isNeedViewConvertResp() bool {
	return len(b.RespItems) > 1
}

var matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

func ToSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToLower(snake)
}

func upFirstChar(fieldParam string) string {
	r := []rune(fieldParam)
	return string(append([]rune{unicode.ToUpper(r[0])}, r[1:]...))
}

func lowerFirstChar(fieldParam string) string {
	r := []rune(fieldParam)
	return string(append([]rune{unicode.ToLower(r[0])}, r[1:]...))
}

type DTO struct {
	Val string
}

func ToCamelCase() string {
	result1 := stringy.New("whs_id").SnakeCase()
	return result1.CamelCase()

}

func genReqAndResp(f *Function, packageMap map[string]*Package) *API {
	api := &API{
		Path:    f.pkg.path,
		Package: f.pkg.name,
		Method:  "",
		Req:     map[string]string{},
		Resp:    nil,
		pkgMap:  packageMap,
	}
	for _, parameter := range f.Func().parameters {
		val := parameter.Definition().String()
		pName := parameter.name
		//println("		param:", pName, val)
		api.Req[pName] = val
		api.ReqFields = append(api.ReqFields, &ReqField{
			Alias: pName,
			Type:  val,
		})
	}

	for i, result := range f.Func().results {
		val := result.def.String()
		api.Resp = append(api.Resp, val)
		api.RespItems = append(api.RespItems, &RespField{
			Alias: fmt.Sprintf("ret%d", i+1),
			Type:  val,
		})
		//println("		ret:", val)
	}
	api.Method = f.name
	api.Func = f.Func()
	return api
}

func ToJSON(data interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		println(err.Error())
	}
	return string(b)
}
func ToPrettyJSON(data interface{}) string {
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		println(err.Error())
	}
	return string(b)
}

func TestName(t *testing.T) {
	println(color.InBold("This is bold"))
	println(color.InUnderline("This is underlined"))
	println(color.InBlack("This is black"))
	println(color.InRed("This is red"))
	println(color.InGreen("This is green"))
	println(color.InYellow("This is yellow"))
	println(color.InBlue("This is blue"))
	println(color.InPurple("This is purple"))
	println(color.InCyan("This is cyan"))
	println(color.InGray("This is gray"))
	println(color.InWhite("This is white"))
}
func isExported(p string) bool {
	return p[0] <= 'Z' && p[0] >= 'A'

}

func TestName2(t *testing.T) {
	var aa = []string{}
	println(len(add11(aa)))
	println(len(add11(aa)))
	println(len(add11(aa)))
	println(len(add11(aa)))
	println(len(add11(aa)))
	println(len(add11(aa)))
}

func add11(aa []string) []string {
	aa = append(aa, "11")
	return aa
}

func TestName1(t *testing.T) {
	result := stringy.New("whsID").CamelCase()
	fmt.Println(result) // HelloManHowAreYou
	result1 := stringy.New("whs_id").SnakeCase()
	fmt.Println(result1.CamelCase()) // HelloManHowAreYou

}

var mskuConvertToPbReqCodeMap = map[string]map[string]string{
	"msku": {
		"GetUpdateOaRuleId":                          "",
		"parseGetCategoryTreeListPbResp":             "func parseGetCategoryTreeListPbResp(resp *pbmsku.GetCategoryTreeListResponse) []*entity.CategoryTree {\n\tvar ret1 = []*entity.CategoryTree{}\n\n\tif jsErr := copier.Copy(resp.GetRet1(), &ret1); jsErr != nil {\n\t\tlogger.LogInfof(\" convert err :%v\", jsErr.Error())\n\t}\n\treturn ret1\n}",
		"parseCalculateMappingInfoPbResp":            "func parseCalculateMappingInfoPbResp(resp *pbmsku.CalculateMappingInfoResponse) []*entity.SKUCalculateMapping {\n\tvar ret1 = []*entity.SKUCalculateMapping{}\n\n\tif len(resp.Ret1) > 0 {\n\t\tif jsErr := copier.Copy(resp.GetRet1(), &ret1); jsErr != nil {\n\t\t\tlogger.LogErrorf(\"json convert err:%v\", jsErr.Error())\n\t\t}\n\t}\n\treturn ret1\n}",
		"toGetSKUItemBySkuIdPbReq":                   "func toGetSKUItemBySkuIdPbReq(skuID string, options *DbOption) (*pbmsku.GetSKUItemBySkuIdRequest, *wmserror.WMSError) {\n\toption := &pbmsku.Option{}\n\tif options != nil {\n\t\toption.UseMaster = convert.Bool(options.UseMaster)\n\t}\n\treq := &pbmsku.GetSKUItemBySkuIdRequest{\n\t\tSkuId: convert.String(skuID),\n\t\tOptions:   option,\n\t}\n\treturn req, nil\n}",
		"toGetSkuListBySkuIDListMngPbReq":            "func toGetSkuListBySkuIDListMngPbReq(skuIDList []string, options *DbOption) (*pbmsku.GetSkuListBySkuIDListMngRequest, *wmserror.WMSError) {\n\toption := &pbmsku.Option{}\n\tif options != nil {\n\t\toption.UseMaster = convert.Bool(options.UseMaster)\n\t}\n\treq := &pbmsku.GetSkuListBySkuIDListMngRequest{\n\t\tSkuIdList: skuIDList,\n\t\tOptions:   option,\n\t}\n\treturn req, nil\n}",
		"toGetExportShopListMngPbReq":                "func toGetExportShopListMngPbReq(params ExportShopRequestItem, whsID string) (*pbmsku.GetExportShopListMngRequest, *wmserror.WMSError) {\n\tvar paramsItem *pbmsku.ExportShopRequestItem\n\tparamsItem = &pbmsku.ExportShopRequestItem{}\n\tif jsErr := copier.Copy(params, paramsItem); jsErr != nil {\n\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t}\n\treq := &pbmsku.GetExportShopListMngRequest{\n\t\tParams: paramsItem,\n\t\tWhsId:  convert.String(whsID),\n\t}\n\treturn req, nil\n}",
		"toGetUpdatePouchPackagingPbReq":             "func toGetUpdatePouchPackagingPbReq(categoryNode *CategoryTreeNodeItem, isPouchPackaging constant.IsPouchPackingStorageType, updateType constant.CategoryAttrUpdateTypeEnum, operator string, categoryIDAttrMap map[int64]*entity.CategoryWhsAttr) (*pbmsku.GetUpdatePouchPackagingRequest, *wmserror.WMSError) {\n\tvar categoryNodeItem *pbmsku.CategoryTreeNodeItem\n\tif categoryNode != nil {\n\t\tcategoryNodeItem = &pbmsku.CategoryTreeNodeItem{}\n\t\tif jsErr := copier.Copy(categoryNode, categoryNodeItem); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\t}\n\tvar categoryIDAttrMapItem []*pbmsku.MapCategoryWhsAttrItem\n\tfor id, attr := range categoryIDAttrMap {\n\t\titem := &pbmsku.CategoryWhsAttrItem{}\n\t\tif jsErr := copier.Copy(attr, item); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\n\t\tcategoryIDAttrMapItem = append(categoryIDAttrMapItem, &pbmsku.MapCategoryWhsAttrItem{\n\t\t\tId:   convert.Int64(id),\n\t\t\tAttr: item,\n\t\t})\n\t}\n\n\treq := &pbmsku.GetUpdatePouchPackagingRequest{\n\t\tCategoryNode:      categoryNodeItem,\n\t\tIsPouchPackaging:  convert.Int64(isPouchPackaging),\n\t\tUpdateType:        convert.Int64(updateType),\n\t\tOperator:          convert.String(operator),\n\t\tCategoryIdAttrMap: categoryIDAttrMapItem,\n\t}\n\treturn req, nil\n}",
		"toUpdateSuggestZoneAndPathwayCorePbReq":     "func toUpdateSuggestZoneAndPathwayCorePbReq(whsID string, deleteZonePathwaysCategoryIds []int64, createZonePathways []*CategoryZonePathwayConfTabItem, whsCategoryIDZonePathwaysMap map[int64][]*entity.CategoryZonePathwayConf, operator string) (*pbmsku.UpdateSuggestZoneAndPathwayCoreRequest, *wmserror.WMSError) {\n\tvar createZonePathwaysItems []*pbmsku.CategoryZonePathwayConfTabItem\n\tif len(createZonePathways) > 0 {\n\t\tcreateZonePathwaysItems = []*pbmsku.CategoryZonePathwayConfTabItem{}\n\t\tif jsErr := copier.Copy(createZonePathways, createZonePathwaysItems); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\t}\n\tvar whsCategoryIDZonePathwaysMapItem []*pbmsku.MapCategoryZonePathwayConfList\n\tfor id, list := range whsCategoryIDZonePathwaysMap {\n\n\t\titemList := []*pbmsku.CategoryZonePathwayConfItem{}\n\n\t\tif jsErr := copier.Copy(list, &itemList); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\t\n\t\titem := &pbmsku.MapCategoryZonePathwayConfList{\n\t\t\tId: convert.Int64(id),\n\t\t\tList: itemList,\n\t\t}\n\t\twhsCategoryIDZonePathwaysMapItem = append(whsCategoryIDZonePathwaysMapItem, item)\n\t}\n\n\treq := &pbmsku.UpdateSuggestZoneAndPathwayCoreRequest{\n\t\tWhsId:                         convert.String(whsID),\n\t\tDeleteZonePathwaysCategoryIds: deleteZonePathwaysCategoryIds,\n\t\tCreateZonePathways:            createZonePathwaysItems,\n\t\tWhsCategoryIdZonePathwaysMap:  whsCategoryIDZonePathwaysMapItem,\n\t\tOperator:                      convert.String(operator),\n\t}\n\treturn req, nil\n}",
		"toBuildCategoryTreeNodesByCategoryMapPbReq": "func toBuildCategoryTreeNodesByCategoryMapPbReq(categoryItem *entity.CategoryTree, parentCategoryChildMap map[int64][]*entity.CategoryTree) (*pbmsku.BuildCategoryTreeNodesByCategoryMapRequest, *wmserror.WMSError) {\n\tvar categoryItemItem *pbmsku.CategoryTreeItem\n\tif categoryItem != nil {\n\t\tcategoryItemItem = &pbmsku.CategoryTreeItem{}\n\t\tif jsErr := copier.Copy(categoryItem, categoryItemItem); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\t}\n\tvar parentCategoryChildMapItem []*pbmsku.MapCategoryTreeItemList\n\tfor id, trees := range parentCategoryChildMap {\n\t\titems := []*pbmsku.CategoryTreeItem{}\n\t\tif jsErr := copier.Copy(trees, &items); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\n\t\tparentCategoryChildMapItem = append(parentCategoryChildMapItem, &pbmsku.MapCategoryTreeItemList{\n\t\t\tId:   convert.Int64(id),\n\t\t\tList: items,\n\t\t})\n\t}\n\treq := &pbmsku.BuildCategoryTreeNodesByCategoryMapRequest{\n\t\tCategoryItem:           categoryItemItem,\n\t\tParentCategoryChildMap: parentCategoryChildMapItem,\n\t}\n\treturn req, nil\n}",
		"toGetUpdateInboundQcChecklistPbReq":         "func toGetUpdateInboundQcChecklistPbReq(whsID string, categoryNode *CategoryTreeNodeItem, inboundQcChecklist string, operator string, categoryIDAttrMap map[int64]*entity.CategoryWhsAttr, categoryUpdateType int64) (*pbmsku.GetUpdateInboundQcChecklistRequest, *wmserror.WMSError) {\n\tvar categoryNodeItem *pbmsku.CategoryTreeNodeItem\n\tif categoryNode != nil {\n\t\tcategoryNodeItem = &pbmsku.CategoryTreeNodeItem{}\n\t\tif jsErr := copier.Copy(categoryNode, categoryNodeItem); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\t}\n\n\tvar categoryIDAttrMapItem []*pbmsku.MapCategoryWhsAttrItem\n\tfor id, attr := range categoryIDAttrMap {\n\t\titem := &pbmsku.CategoryWhsAttrItem{}\n\t\tif jsErr := copier.Copy(attr, item); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\n\t\tcategoryIDAttrMapItem = append(categoryIDAttrMapItem, &pbmsku.MapCategoryWhsAttrItem{\n\t\t\tId:   convert.Int64(id),\n\t\t\tAttr: item,\n\t\t})\n\t}\n\n\treq := &pbmsku.GetUpdateInboundQcChecklistRequest{\n\t\tWhsId:              convert.String(whsID),\n\t\tCategoryNode:       categoryNodeItem,\n\t\tInboundQcChecklist: convert.String(inboundQcChecklist),\n\t\tOperator:           convert.String(operator),\n\t\tCategoryIdAttrMap:  categoryIDAttrMapItem,\n\t\tCategoryUpdateType: convert.Int64(categoryUpdateType),\n\t}\n\treturn req, nil\n}",
		"toGetUpdateOaRuleIdPbReq":                   "func toGetUpdateOaRuleIdPbReq(categoryNode *CategoryTreeNodeItem, oaRuleId string, operator string, categoryIDAttrMap map[int64]*entity.CategoryWhsAttr) (*pbmsku.GetUpdateOaRuleIdRequest, *wmserror.WMSError) {\n\tvar categoryNodeItem *pbmsku.CategoryTreeNodeItem\n\tif categoryNode != nil {\n\t\tcategoryNodeItem = &pbmsku.CategoryTreeNodeItem{}\n\t\tif jsErr := copier.Copy(categoryNode, categoryNodeItem); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\t}\n\tvar categoryIDAttrMapItem []*pbmsku.MapCategoryWhsAttrItem\n\tfor id, attr := range categoryIDAttrMap {\n\t\titem := &pbmsku.CategoryWhsAttrItem{}\n\t\tif jsErr := copier.Copy(attr, item); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())\n\t\t}\n\n\t\tcategoryIDAttrMapItem = append(categoryIDAttrMapItem, &pbmsku.MapCategoryWhsAttrItem{\n\t\t\tId:   convert.Int64(id),\n\t\t\tAttr: item,\n\t\t})\n\t}\n\n\treq := &pbmsku.GetUpdateOaRuleIdRequest{\n\t\tCategoryNode:      categoryNodeItem,\n\t\tOaRuleId:          convert.String(oaRuleId),\n\t\tOperator:          convert.String(operator),\n\t\tCategoryIdAttrMap: categoryIDAttrMapItem,\n\t}\n\treturn req, nil\n}",

		//resp
		"parseCountShopByMerchantIDsPbResp":                    "func parseCountShopByMerchantIDsPbResp(resp *pbmsku.CountShopByMerchantIDsResponse) (map[uint64]int64, *wmserror.WMSError) {\n\tvar ret1 = map[uint64]int64{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMVal()\n\t}\n\treturn ret1, err\n}",
		"parseGetSKUCalculateMappingPbResp":                    "func parseGetSKUCalculateMappingPbResp(resp *pbmsku.GetSKUCalculateMappingResponse) (map[string][]string, *wmserror.WMSError) {\n\tvar ret1 = map[string][]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()]=item.GetMVals()\t\n\t}\n\n\treturn ret1, err\n}",
		"parseGetSkuIsHeavyMapByWhsIdAndSkuIdListPbResp":       "func parseGetSkuIsHeavyMapByWhsIdAndSkuIdListPbResp(resp *pbmsku.GetSkuIsHeavyMapByWhsIdAndSkuIdListResponse) (map[string]bool, *wmserror.WMSError) {\n\tvar ret1 = map[string]bool{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMValue() == \"1\"\n\t}\n\treturn ret1, err\n}",
		"parseGetSkuIsBulKyMapByWhsIdAndSkuIdListPbResp":       "func parseGetSkuIsBulKyMapByWhsIdAndSkuIdListPbResp(resp *pbmsku.GetSkuIsBulKyMapByWhsIdAndSkuIdListResponse) (map[string]bool, *wmserror.WMSError) {\n\tvar ret1 = map[string]bool{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMValue() == \"1\"\n\t}\n\treturn ret1, err\n}",
		"parseGetSKU2CalculateMappingPbResp":                   "func parseGetSKU2CalculateMappingPbResp(resp *pbmsku.GetSKU2CalculateMappingResponse) (map[string][]string, map[string]string, *wmserror.WMSError) {\n\tvar ret1 = map[string][]string{}\n\tvar ret2 = map[string]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMVals()\n\t}\n\tfor _, item := range resp.GetRet2() {\n\t\tret2[item.GetMKey()] = item.GetMValue()\n\t}\n\n\treturn ret1, ret2, err\n}",
		"parseGetSKUsDateFormatMapPbResp":                      "func parseGetSKUsDateFormatMapPbResp(resp *pbmsku.GetSKUsDateFormatMapResponse) (map[string]*entity.SkuProdExpiryDateFormatTab, *wmserror.WMSError) {\n\tvar ret1 = map[string]*entity.SkuProdExpiryDateFormatTab{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tdbItem := &entity.SkuProdExpiryDateFormatTab{}\n\t\tif jsErr := copier.Copy(item, dbItem); jsErr != nil {\n\t\t\treturn ret1, wmserror.NewError(constant.ErrBadRequest, \"json convert err:\", jsErr.Error())\n\t\t}\n\t\tret1[item.GetSkuId()] = dbItem\n\t}\n\treturn ret1, err\n}",
		"parseGetSKUTagBySkuIDPbResp":                          "func parseGetSKUTagBySkuIDPbResp(resp *pbmsku.GetSKUTagBySkuIDResponse) (map[string][]*entity.SKUTagEntity, *wmserror.WMSError) {\n\tvar ret1 = map[string][]*entity.SKUTagEntity{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tdbItems := []*entity.SKUTagEntity{}\n\t\tif jsErr := copier.Copy(item.GetTags(), &dbItems); jsErr != nil {\n\t\t\treturn ret1, wmserror.NewError(constant.ErrBadRequest, \"json convert err:\", jsErr.Error())\n\t\t}\n\t\tret1[item.GetSkuId()] = dbItems\n\t}\n\treturn ret1, err\n}",
		"parseGetAllCategoryMapByCountryPbResp":                "func parseGetAllCategoryMapByCountryPbResp(resp *pbmsku.GetAllCategoryMapByCountryResponse) (map[int64]*entity.CategoryTree, *wmserror.WMSError) {\n\tvar ret1 = map[int64]*entity.CategoryTree{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tdbItem := &entity.CategoryTree{}\n\t\tif jsErr := copier.Copy(item.GetItem(), dbItem); jsErr != nil {\n\t\t\treturn ret1, wmserror.NewError(constant.ErrBadRequest, \"json convert err:\", jsErr.Error())\n\t\t}\n\t\tret1[item.GetId()] = dbItem\n\t}\n\n\treturn ret1, err\n}",
		"parseGetSKUCalculateMappingAndSKUListWithSlicePbResp": "func parseGetSKUCalculateMappingAndSKUListWithSlicePbResp(resp *pbmsku.GetSKUCalculateMappingAndSKUListWithSliceResponse) (map[string][]string, map[string]string, []string, *wmserror.WMSError) {\n\tvar ret1 = map[string][]string{}\n\tvar ret2 = map[string]string{}\n\tvar ret3 []string\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMVals()\n\t}\n\tfor _, item := range resp.GetRet2() {\n\t\tret2[item.GetMKey()] = item.GetMValue()\n\t}\n\n\tret3 = resp.GetRet3()\n\treturn ret1, ret2, ret3, err\n}",
		"parseGetAllSKU2CalculateMappingPbResp":                "func parseGetAllSKU2CalculateMappingPbResp(resp *pbmsku.GetAllSKU2CalculateMappingResponse) (map[string][]string, map[string]string, *wmserror.WMSError) {\n\tvar ret1 = map[string][]string{}\n\tvar ret2 = map[string]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMVals()\n\t}\n\tfor _, item := range resp.GetRet2() {\n\t\tret2[item.GetMKey()] = item.GetMValue()\n\t}\n\treturn ret1, ret2, err\n}",
		"parseGetSKUTagBySkuWhsAttrPbResp":                     "func parseGetSKUTagBySkuWhsAttrPbResp(resp *pbmsku.GetSKUTagBySkuWhsAttrResponse) (map[string][]*entity.SKUTagEntity, *wmserror.WMSError) {\n\tvar ret1 = map[string][]*entity.SKUTagEntity{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tdbItems := []*entity.SKUTagEntity{}\n\t\tif jsErr := copier.Copy(item.GetTags(), &dbItems); jsErr != nil {\n\t\t\treturn ret1, wmserror.NewError(constant.ErrBadRequest, \"json convert err:\", jsErr.Error())\n\t\t}\n\t\tret1[item.GetSkuId()] = dbItems\n\t}\n\treturn ret1, err\n}",
		"parseSearchCategoryZonePathwayMngPbResp":              "func parseSearchCategoryZonePathwayMngPbResp(resp *pbmsku.SearchCategoryZonePathwayMngResponse) (map[int64][]string, map[int64][]string, *wmserror.WMSError) {\n\tvar ret1 = map[int64][]string{}\n\tvar ret2 = map[int64][]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMVals()\n\t}\n\tfor _, item := range resp.GetRet2() {\n\t\tret2[item.GetMKey()] = item.GetMVals()\n\t}\n\treturn ret1, ret2, err\n}",
		"parseGetSkuIsBulKyMapByWhsIdAndSkuItemListPbResp":     "func parseGetSkuIsBulKyMapByWhsIdAndSkuItemListPbResp(resp *pbmsku.GetSkuIsBulKyMapByWhsIdAndSkuItemListResponse) (map[string]bool, *wmserror.WMSError) {\n\tvar ret1 = map[string]bool{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMValue() == \"1\"\n\t}\n\treturn ret1, err\n}",
		"parseGetSupplierNameMappingBySupplierIDListMngPbResp": "func parseGetSupplierNameMappingBySupplierIDListMngPbResp(resp *pbmsku.GetSupplierNameMappingBySupplierIDListMngResponse) (map[int64]string, *wmserror.WMSError) {\n\tvar ret1 = map[int64]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tid, cpErr := convert.StringToInt64(item.GetMKey())\n\t\tif cpErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrDataConvertFail, cpErr.Error())\n\t\t}\n\t\tret1[id] = item.GetMValue()\n\t}\n\treturn ret1, err\n}",
		//"parseGetSkuScbsCannotUpdateFieldsTypeMapPbResp":       "func parseGetSupplierNameMappingBySupplierIDListMngPbResp(resp *pbmsku.GetSupplierNameMappingBySupplierIDListMngResponse) (map[int64]string, *wmserror.WMSError) {\n\tvar ret1 = map[int64]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tid, cpErr := convert.StringToInt64(item.GetMKey())\n\t\tif cpErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrDataConvertFail, cpErr.Error())\n\t\t}\n\t\tret1[id] = item.GetMValue()\n\t}\n\treturn ret1, err\n}",
		"parseGetParentCategoryIDChildCategoryMapPbResp":     "func parseGetParentCategoryIDChildCategoryMapPbResp(resp *pbmsku.GetParentCategoryIDChildCategoryMapResponse) (map[int64][]*entity.CategoryTree, *wmserror.WMSError) {\n\tvar ret1 = map[int64][]*entity.CategoryTree{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tdbItems := []*entity.CategoryTree{}\n\t\tif jsErr := copier.Copy(item.GetList(), &dbItems); jsErr != nil {\n\t\t\treturn ret1, wmserror.NewError(constant.ErrBadRequest, \"json convert err:\", jsErr.Error())\n\t\t}\n\t\tret1[item.GetId()] = dbItems\n\t}\n\treturn ret1, err\n}",
		"parseMGetSkuOARuleIDPbResp":                         "func parseMGetSkuOARuleIDPbResp(resp *pbmsku.MGetSkuOARuleIDResponse) (map[string]string, *wmserror.WMSError) {\n\tvar ret1 = map[string]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMValue()\n\t}\n\treturn ret1, err\n}",
		"parseGetSkuIsBulKyTypeMapByWhsIdAndSkuIdListPbResp": "func parseGetSkuIsBulKyTypeMapByWhsIdAndSkuIdListPbResp(resp *pbmsku.GetSkuIsBulKyTypeMapByWhsIdAndSkuIdListResponse) (map[string]constant.SkuSizeType, *wmserror.WMSError) {\n\tvar ret1 = map[string]constant.SkuSizeType{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tid,cpErr:=convert.StringToInt64(item.GetMKey())\n\t\tif cpErr != nil {\n\t\t\treturn nil,wmserror.NewError(constant.ErrDataConvertFail,cpErr.Error())\n\t\t}\n\t\tret1[item.GetMKey()] = constant.SkuSizeType(id)\n\t}\n\n\treturn ret1, err\n}",
		"parseGetSKUCalculateMappingAndSKUListPbResp":        "func parseGetSKUCalculateMappingAndSKUListPbResp(resp *pbmsku.GetSKUCalculateMappingAndSKUListResponse) (map[string][]string, map[string]string, []string, *wmserror.WMSError) {\n\tvar ret1 = map[string][]string{}\n\tvar ret2 = map[string]string{}\n\tvar ret3 []string\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMVals()\n\t}\n\tfor _, item := range resp.GetRet2() {\n\t\tret2[item.GetMKey()] = item.GetMValue()\n\t}\n\n\tret3 = resp.GetRet3()\n\treturn ret1, ret2, ret3, err\n}",
		"parseGetSkuIDListMbnMapPbResp":                      "func parseGetSkuIDListMbnMapPbResp(resp *pbmsku.GetSkuIDListMbnMapResponse) (map[string][]string, *wmserror.WMSError) {\n\tvar ret1 = map[string][]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMVals()\n\t}\n\treturn ret1, err\n}",
		"parseGetSkuMtSKUMapPbResp":                          "func parseGetSkuMtSKUMapPbResp(resp *pbmsku.GetSkuMtSKUMapResponse) (map[string]string, *wmserror.WMSError) {\n\tvar ret1 = map[string]string{}\n\tvar err *wmserror.WMSError\n\n\tfor _, item := range resp.GetRet1() {\n\t\tret1[item.GetMKey()] = item.GetMValue()\n\t}\n\n\treturn ret1, err\n}",
	},
}

var parseReqItemsCodeMap = map[string]map[string]string{
	"msku": {
		"parseBuildCategoryTreeNodesByCategoryMapPbRequest":                "func parseBuildCategoryTreeNodesByCategoryMapPbRequest(req *pbmsku.BuildCategoryTreeNodesByCategoryMapRequest) (*entity.CategoryTree, map[int64][]*entity.CategoryTree, *wmserror.WMSError) {\n\tvar categoryItem *entity.CategoryTree\n\tif req.CategoryItem != nil {\n\t\tcategoryItem = &entity.CategoryTree{}\n\t\tif jsErr := copier.Copy(req.CategoryItem, categoryItem); jsErr != nil {\n\t\t\treturn nil, nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\tvar parentCategoryChildMap = map[int64][]*entity.CategoryTree{}\n\tfor _, mapItem := range req.ParentCategoryChildMap {\n\t\titems := []*entity.CategoryTree{}\n\t\tif jsErr := copier.Copy(mapItem.List, &items); jsErr != nil {\n\t\t\treturn nil, nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t\tparentCategoryChildMap[mapItem.GetId()] = items\n\t}\n\n\treturn categoryItem, parentCategoryChildMap, nil\n}",
		"parseCheckAndGetUpdateCategorySuggestZoneAndPathwayDataPbRequest": "func parseCheckAndGetUpdateCategorySuggestZoneAndPathwayDataPbRequest(req *pbmsku.CheckAndGetUpdateCategorySuggestZoneAndPathwayDataRequest) (int64, string, string, []*entity.CategoryZonePathwayConf, *wmserror.WMSError) {\n\tvar categoryID = req.GetCategoryId()\n\tvar updateSuggestZoneWithSemicolon = req.GetUpdateSuggestZoneWithSemicolon()\n\tvar updateSuggestPathwayWithSemicolon = req.GetUpdateSuggestPathwayWithSemicolon()\n\tvar categoryIDZoneAndPathwayConfs []*entity.CategoryZonePathwayConf\n\tif req.CategoryIdZoneAndPathwayConfs != nil {\n\t\tcategoryIDZoneAndPathwayConfs = []*entity.CategoryZonePathwayConf{}\n\t\tif jsErr := copier.Copy(req.CategoryIdZoneAndPathwayConfs, categoryIDZoneAndPathwayConfs); jsErr != nil {\n\t\t\treturn 0, \"\", \"\", nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn categoryID, updateSuggestZoneWithSemicolon, updateSuggestPathwayWithSemicolon, categoryIDZoneAndPathwayConfs, nil\n}",
		"parseCountShopByMerchantIDsPbRequest":                             "func parseCountShopByMerchantIDsPbRequest(req *pbmsku.CountShopByMerchantIDsRequest) (string, []uint64, *wmserror.WMSError) {\n\treturn req.GetCountry(), req.GetMerchantIDs(), nil\n}",
		"parseCountSupplierListByConditionMngPbRequest":                    "func parseCountSupplierListByConditionMngPbRequest(req *pbmsku.CountSupplierListByConditionMngRequest) (msku.GetSupplierListCondition, *wmserror.WMSError) {\n\tvar condition msku.GetSupplierListCondition\n\tif req.Condition != nil {\n\t\tif jsErr := copier.Copy(req.Condition, &condition); jsErr != nil {\n\t\t\treturn msku.GetSupplierListCondition{}, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn condition, nil\n}",
		"parseCreateSkuPrintMappingPbRequest":                              "func parseCreateSkuPrintMappingPbRequest(req *pbmsku.CreateSkuPrintMappingRequest) (*entity.SkuPrintMappingEntity, *wmserror.WMSError) {\n\tvar entityItem *entity.SkuPrintMappingEntity\n\tif req.Entity != nil {\n\t\tentityItem = &entity.SkuPrintMappingEntity{}\n\t\tif jsErr := copier.Copy(req.Entity, entityItem); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn entityItem, nil\n}",
		"parseCurrentGetSkuListBySkuIDListMngPbRequest":                    "func parseCurrentGetSkuListBySkuIDListMngPbRequest(req *pbmsku.CurrentGetSkuListBySkuIDListMngRequest) ([]string, int, *wmserror.WMSError) {\n\tvar skuIDList = req.GetSkuIdList()\n\treturn skuIDList, int(req.GetOneQueryCount()), nil\n}",
		"parseFuzzySearchCategoryIdOrNameWithConditionRepoPbRequest":       "func parseFuzzySearchCategoryIdOrNameWithConditionRepoPbRequest(req *pbmsku.FuzzySearchCategoryIdOrNameWithConditionRepoRequest) (string, string, []constant.CategoryLevel, *paginator.PageIn, *wmserror.WMSError) {\n\tvar country = req.GetCountry()\n\tvar categoryIdOrName = req.GetCategoryIdOrName()\n\tvar levelItems []constant.CategoryLevel\n\tfor _, item := range req.Level {\n\t\tlevelItems = append(levelItems, constant.CategoryLevel(item))\n\t}\n\n\tvar pageIn *paginator.PageIn\n\tif pageInItem := req.PageIn; pageInItem != nil {\n\t\tpageIn = &paginator.PageIn{\n\t\t\tPageno:     pageInItem.GetPageno(),\n\t\t\tCount:      pageInItem.GetCount(),\n\t\t\tOrderBy:    pageInItem.GetOrderBy(),\n\t\t\tIsGetTotal: pageInItem.GetIsGetTotal(),\n\t\t}\n\t}\n\n\treturn country, categoryIdOrName, levelItems, pageIn, nil\n}",
		"parseFuzzySearchSupplierPbRequest":                                "func parseFuzzySearchSupplierPbRequest(req *pbmsku.FuzzySearchSupplierRequest) (msku.FuzzyQrySupplierCondition, *paginator.PageIn, *wmserror.WMSError) {\n\tvar condition msku.FuzzyQrySupplierCondition\n\tif req.Condition != nil {\n\t\tif jsErr := copier.Copy(req.Condition, &condition); jsErr != nil {\n\t\t\treturn msku.FuzzyQrySupplierCondition{}, nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\n\tvar pageIn *paginator.PageIn\n\tif pageInItem := req.PageIn; pageInItem != nil {\n\t\tpageIn = &paginator.PageIn{\n\t\t\tPageno:     pageInItem.GetPageno(),\n\t\t\tCount:      pageInItem.GetCount(),\n\t\t\tOrderBy:    pageInItem.GetOrderBy(),\n\t\t\tIsGetTotal: pageInItem.GetIsGetTotal(),\n\t\t}\n\t}\n\n\treturn condition, pageIn, nil\n}",
		"parseGetRegionSKUItemWithIDPbRequest":                             "func parseGetRegionSKUItemWithIDPbRequest(req *pbmsku.GetRegionSKUItemWithIDRequest) (int64, int64, int, *wmserror.WMSError) {\n\tvar miniID = req.GetMiniId()\n\tvar maxID = req.GetMaxId()\n\tvar limit = req.GetLimit()\n\treturn miniID, maxID, int(limit), nil\n}",
		"parseGetSKUCalculateMappingEntityListByConditionPbRequest":        "func parseGetSKUCalculateMappingEntityListByConditionPbRequest(req *pbmsku.GetSKUCalculateMappingEntityListByConditionRequest) (msku.SkuCalculateMappingQryCondition, *wmserror.WMSError) {\n\tvar condition msku.SkuCalculateMappingQryCondition\n\tif req.Condition != nil {\n\t\tif jsErr := copier.Copy(req.Condition, &condition); jsErr != nil {\n\t\t\treturn msku.SkuCalculateMappingQryCondition{}, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn condition, nil\n}",
		"parseGetSKUItemBySkuIdPbRequest":                                  "func parseGetSKUItemBySkuIdPbRequest(req *pbmsku.GetSKUItemBySkuIdRequest) (string, db_config.Option, *wmserror.WMSError) {\n\tvar skuID = req.GetSkuId()\n\tvar option db_config.Option\t\t\n\tif req.Options != nil {\n\t\toption = db_config.DBUseOption(req.Options.GetUseMaster())\t\n\t}\n\t\n\treturn skuID, option, nil\n}",
		"parseGetSKUUnitListByConditionPbRequest":                          "func parseGetSKUUnitListByConditionPbRequest(req *pbmsku.GetSKUUnitListByConditionRequest) (msku.SkuUnitQueryCondition, *wmserror.WMSError) {\n\tvar condition msku.SkuUnitQueryCondition\n\tif req.Condition != nil {\n\t\tif jsErr := copier.Copy(req.Condition, &condition); jsErr != nil {\n\t\t\treturn msku.SkuUnitQueryCondition{}, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn condition, nil\n}",
		"parseGetSkuSyncFailMessagePbRequest":                              "func parseGetSkuSyncFailMessagePbRequest(req *pbmsku.GetSkuSyncFailMessageRequest) (*paginator.PageIn, *msku.SkuSyncFailMessageCondition, *wmserror.WMSError) {\n\n\tvar in *paginator.PageIn\n\tif pageInItem := req.In; pageInItem != nil {\n\t\tin = &paginator.PageIn{\n\t\t\tPageno:     pageInItem.GetPageno(),\n\t\t\tCount:      pageInItem.GetCount(),\n\t\t\tOrderBy:    pageInItem.GetOrderBy(),\n\t\t\tIsGetTotal: pageInItem.GetIsGetTotal(),\n\t\t}\n\t}\n\n\tvar condition *msku.SkuSyncFailMessageCondition\n\tif req.Condition != nil {\n\t\tcondition = &msku.SkuSyncFailMessageCondition{}\n\t\tif jsErr := copier.Copy(req.Condition, condition); jsErr != nil {\n\t\t\treturn nil, nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn in, condition, nil\n}",
		"parseGetSupplierByIdMngPbRequest":                                 "func parseGetSupplierByIdMngPbRequest(req *pbmsku.GetSupplierByIdMngRequest) (*string, *wmserror.WMSError) {\n\treturn req.SupplierId, nil\n}",
		"parseGetUpdateInboundQcChecklistPbRequest":                        "func parseGetUpdateInboundQcChecklistPbRequest(req *pbmsku.GetUpdateInboundQcChecklistRequest) (string, *msku.CategoryTreeNode, string, string, map[int64]*entity.CategoryWhsAttr, int64, *wmserror.WMSError) {\n\tvar whsID = req.GetWhsId()\n\tvar categoryNode *msku.CategoryTreeNode\n\tif req.CategoryNode != nil {\n\t\tcategoryNode = &msku.CategoryTreeNode{}\n\t\tif jsErr := copier.Copy(req.CategoryNode, categoryNode); jsErr != nil {\n\t\t\treturn \"\", nil, \"\", \"\", nil, 0, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\tvar inboundQcChecklist = req.GetInboundQcChecklist()\n\tvar operator = req.GetOperator()\n\tcategoryIDAttrMap, err := toWhsAttrMap(req.CategoryIdAttrMap)\n\tif err != nil {\n\t\treturn \"\", nil, \"\", \"\", nil, 0, err.Mark()\n\t}\n\tvar categoryUpdateType = req.GetCategoryUpdateType()\n\treturn whsID, categoryNode, inboundQcChecklist, operator, categoryIDAttrMap, categoryUpdateType, nil\n}\n\nfunc toWhsAttrMap(mapItems []*pbmsku.MapCategoryWhsAttrItem) (map[int64]*entity.CategoryWhsAttr, *wmserror.WMSError) {\n\tvar categoryIDAttrMap = map[int64]*entity.CategoryWhsAttr{}\n\tfor _, item := range mapItems {\n\t\tattr := &entity.CategoryWhsAttr{}\n\t\tif jsErr := copier.Copy(item.GetAttr(), attr); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t\tcategoryIDAttrMap[item.GetId()] = attr\n\t}\n\treturn categoryIDAttrMap, nil\n}",
		"parseGetUpdateOaRuleIdPbRequest":                                  "func parseGetUpdateOaRuleIdPbRequest(req *pbmsku.GetUpdateOaRuleIdRequest) (*msku.CategoryTreeNode, string, string, map[int64]*entity.CategoryWhsAttr, *wmserror.WMSError) {\n\tvar categoryNode *msku.CategoryTreeNode\n\tif req.CategoryNode != nil {\n\t\tcategoryNode = &msku.CategoryTreeNode{}\n\t\tif jsErr := copier.Copy(req.CategoryNode, categoryNode); jsErr != nil {\n\t\t\treturn nil, \"\", \"\", nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\tvar oaRuleId = req.GetOaRuleId()\n\tvar operator = req.GetOperator()\n\tcategoryIDAttrMap, err := toWhsAttrMap(req.CategoryIdAttrMap)\n\tif err != nil {\n\t\treturn nil, \"\", \"\", nil, err.Mark()\n\t}\n\treturn categoryNode, oaRuleId, operator, categoryIDAttrMap, nil\n}",
		"parseQueryCategoryTreeMngPbRequest":                               "func parseQueryCategoryTreeMngPbRequest(req *pbmsku.QueryCategoryTreeMngRequest) (string, int64, string, *wmserror.WMSError) {\n\tvar country = req.GetCountry()\n\tvar parent_category_id = req.GetParentCategoryId()\n\tvar whsID = req.GetWhsId()\n\treturn country, parent_category_id, whsID, nil\n}",
		"parseSearchSKUBatchMngPbRequest":                                  "func parseSearchSKUBatchMngPbRequest(req *pbmsku.SearchSKUBatchMngRequest) (*msku.SearchSKUBatchCondition, *paginator.PageIn, *wmserror.WMSError) {\n\tvar condition *msku.SearchSKUBatchCondition\n\tif req.Condition != nil {\n\t\tcondition = &msku.SearchSKUBatchCondition{}\n\t\tif jsErr := copier.Copy(req.Condition, condition); jsErr != nil {\n\t\t\treturn nil, nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\n\tvar in *paginator.PageIn\n\tif pageInItem := req.In; pageInItem != nil {\n\t\tin = &paginator.PageIn{\n\t\t\tPageno:     pageInItem.GetPageno(),\n\t\t\tCount:      pageInItem.GetCount(),\n\t\t\tOrderBy:    pageInItem.GetOrderBy(),\n\t\t\tIsGetTotal: pageInItem.GetIsGetTotal(),\n\t\t}\n\t}\n\n\treturn condition, in, nil\n}",
		"parseGetSkuListBySkuIDListMngPbRequest":                           "func parseGetSkuListBySkuIDListMngPbRequest(req *pbmsku.GetSkuListBySkuIDListMngRequest) ([]string, db_config.Option, *wmserror.WMSError) {\n\tvar skuIDList = req.GetSkuIdList()\n\tvar option db_config.Option\n\tif req.Options != nil {\n\t\toption = db_config.DBUseOption(req.Options.GetUseMaster())\n\t}\n\treturn skuIDList, option, nil\n}",
		"parseGetSupplierListByConditionMngPbRequest":                      "func parseGetSupplierListByConditionMngPbRequest(req *pbmsku.GetSupplierListByConditionMngRequest) (msku.GetSupplierListCondition, *wmserror.WMSError) {\n\tvar condition msku.GetSupplierListCondition\n\tif req.Condition != nil {\n\t\tif jsErr := copier.Copy(req.Condition, &condition); jsErr != nil {\n\t\t\treturn msku.GetSupplierListCondition{}, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn condition, nil\n}",
		"parseGetSupplierSkuByLeftLikeConditionPbRequest":                  "func parseGetSupplierSkuByLeftLikeConditionPbRequest(req *pbmsku.GetSupplierSkuByLeftLikeConditionRequest) (msku.SearchSupplierSKULikeCondition, *wmserror.WMSError) {\n\tvar condition msku.SearchSupplierSKULikeCondition\n\tif req.Condition != nil {\n\t\tif jsErr := copier.Copy(req.Condition, &condition); jsErr != nil {\n\t\t\treturn msku.SearchSupplierSKULikeCondition{}, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn condition, nil\n}",
		"parseGetUpdateLifeCycleRulePbRequest":                             "func parseGetUpdateLifeCycleRulePbRequest(req *pbmsku.GetUpdateLifeCycleRuleRequest) (*msku.CategoryTreeNode, string, string, constant.CategoryUpdateType, *wmserror.WMSError) {\n\tvar categoryNode *msku.CategoryTreeNode\n\tif req.CategoryNode != nil {\n\t\tcategoryNode = &msku.CategoryTreeNode{}\n\t\tif jsErr := copier.Copy(req.CategoryNode, categoryNode); jsErr != nil {\n\t\t\treturn nil, \"\", \"\", 0, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\tvar lifeCycleRule = req.GetLifeCycleRule()\n\tvar operator = req.GetOperator()\n\tvar updateType = req.GetUpdateType()\n\treturn categoryNode, lifeCycleRule, operator, updateType, nil\n}",
		"parseSearchSkuModifyLogPbRequest":                                 "func parseSearchSkuModifyLogPbRequest(req *pbmsku.SearchSkuModifyLogRequest) (msku.SearchSkuLogCondition, *wmserror.WMSError) {\n\tvar cond msku.SearchSkuLogCondition\n\tif req.Cond != nil {\n\t\tif jsErr := copier.Copy(req.Cond, &cond); jsErr != nil {\n\t\t\treturn msku.SearchSkuLogCondition{}, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn cond, nil\n}",
		"parseSearchSkuPrintMappingPbRequest":                              "func parseSearchSkuPrintMappingPbRequest(req *pbmsku.SearchSkuPrintMappingRequest) (msku.SkuPrintMappingQryCondition, *wmserror.WMSError) {\n\tvar condition msku.SkuPrintMappingQryCondition\n\tif req.Condition != nil {\n\t\tif jsErr := copier.Copy(req.Condition, &condition); jsErr != nil {\n\t\t\treturn msku.SkuPrintMappingQryCondition{}, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn condition, nil\n}",
		"parseUpdateSuggestZoneAndPathwayCorePbRequest":                    "func parseUpdateSuggestZoneAndPathwayCorePbRequest(req *pbmsku.UpdateSuggestZoneAndPathwayCoreRequest) (string, []int64, []*msku.CategoryZonePathwayConfTab, map[int64][]*entity.CategoryZonePathwayConf, string, *wmserror.WMSError) {\n\tvar whsID = req.GetWhsId()\n\tvar deleteZonePathwaysCategoryIds = req.GetDeleteZonePathwaysCategoryIds()\n\tvar createZonePathways []*msku.CategoryZonePathwayConfTab\n\tif req.CreateZonePathways != nil {\n\t\tcreateZonePathways = []*msku.CategoryZonePathwayConfTab{}\n\t\tif jsErr := copier.Copy(req.CreateZonePathways, createZonePathways); jsErr != nil {\n\t\t\treturn \"\", nil, nil, nil, \"\", wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\tvar whsCategoryIDZonePathwaysMap = map[int64][]*entity.CategoryZonePathwayConf{}\n\tfor _, mapItemList := range req.WhsCategoryIdZonePathwaysMap {\n\t\titems := []*entity.CategoryZonePathwayConf{}\n\t\tif jsErr := copier.Copy(mapItemList.List, &items); jsErr != nil {\n\t\t\treturn \"\", nil, nil, nil, \"\", wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t\twhsCategoryIDZonePathwaysMap[mapItemList.GetId()] = items\n\t}\n\tvar operator = req.GetOperator()\n\treturn whsID, deleteZonePathwaysCategoryIds, createZonePathways, whsCategoryIDZonePathwaysMap, operator, nil\n}",
		"parseUpdateSupplierDateFormatPbRequest":                           "func parseUpdateSupplierDateFormatPbRequest(req *pbmsku.UpdateSupplierDateFormatRequest) (*string, map[string]interface{}, *wmserror.WMSError) {\n\tupdateSupplierDateFormatMap, err := pbconvert.ConvertUpdateMaps(req.GetUpdateSupplierDateFormatMap())\n\tif err != nil {\n\t\treturn nil, nil, err.Mark()\n\t}\n\treturn req.SupplierId, updateSupplierDateFormatMap, nil\n}",
		"parseGetSkuDefaultMappingByConditionPbRequest":                    "func parseGetSkuDefaultMappingByConditionPbRequest(req *pbmsku.GetSkuDefaultMappingByConditionRequest) (msku.SkuDefaultMappingQryCondition, *wmserror.WMSError) {\n\tvar condition msku.SkuDefaultMappingQryCondition\n\tif req.Condition != nil {\n\t\tif jsErr := copier.Copy(req.Condition, &condition); jsErr != nil {\n\t\t\treturn msku.SkuDefaultMappingQryCondition{}, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t}\n\treturn condition, nil\n}",
		"parseGetSKUCalculateMappingAndSKUListWithSlicePbRequest":          "func parseGetSKUCalculateMappingAndSKUListWithSlicePbRequest(req *pbmsku.GetSKUCalculateMappingAndSKUListWithSliceRequest) ([]string, bool, int, *wmserror.WMSError) {\n\tvar skuList = req.GetSkuList()\n\tvar reverse = req.GetReverse()\n\tvar step = req.GetStep()\n\treturn skuList, reverse, int(step), nil\n}",
		"parseSearchSkuTemperatureControlIsHotBySkuListWithSlicePbRequest": "func parseSearchSkuTemperatureControlIsHotBySkuListWithSlicePbRequest(req *pbmsku.SearchSkuTemperatureControlIsHotBySkuListWithSliceRequest) (string, []string, bool, int, *wmserror.WMSError) {\n\tvar country = req.GetCountry()\n\tvar skuList = req.GetSkuList()\n\tvar replica = req.GetReplica()\n\tvar step = req.GetStep()\n\treturn country, skuList, replica, int(step), nil\n}",

		//convert to resp
		"toMGetSkuOARuleIDPbResp":                           "func toMGetSkuOARuleIDPbResp(ret1 map[string]string) (*pbmsku.MGetSkuOARuleIDResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.MGetSkuOARuleIDResponse{\n\t\tRet1: toMapItemByStrMap(ret1),\n\t}\n\treturn resp, nil\n}\n\nfunc toMapItemByStrMap(ret1 map[string]string) []*pbmsku.MapItem {\n\tmapItems := []*pbmsku.MapItem{}\n\tfor k, v := range ret1 {\n\t\tmapItems = append(mapItems, &pbmsku.MapItem{\n\t\t\tMKey:   convert.String(k),\n\t\t\tMValue: convert.String(v),\n\t\t\tMType:  convert.String(\"string\"),\n\t\t})\n\t}\n\treturn mapItems\n}",
		"toSearchCategoryZonePathwayMngPbResp":              "func toSearchCategoryZonePathwayMngPbResp(ret1 map[int64][]string, ret2 map[int64][]string) (*pbmsku.SearchCategoryZonePathwayMngResponse, *wmserror.WMSError) {\n\tret1Items := []*pbmsku.MapIntStrsItem{}\n\n\tfor id, items := range ret1 {\n\t\tret1Items = append(ret1Items, &pbmsku.MapIntStrsItem{\n\t\t\tMKey:  convert.Int64(id),\n\t\t\tMVals: items,\n\t\t})\n\t}\n\n\tret2Items := []*pbmsku.MapIntStrsItem{}\n\tfor id, items := range ret2 {\n\t\tret2Items = append(ret2Items, &pbmsku.MapIntStrsItem{\n\t\t\tMKey:  convert.Int64(id),\n\t\t\tMVals: items,\n\t\t})\n\t}\n\n\tresp := &pbmsku.SearchCategoryZonePathwayMngResponse{\n\t\tRet1: ret1Items,\n\t\tRet2: ret2Items,\n\t}\n\treturn resp, nil\n}",
		"toCountShopByMerchantIDsPbResp":                    "func toCountShopByMerchantIDsPbResp(ret1 map[uint64]int64) (*pbmsku.CountShopByMerchantIDsResponse, *wmserror.WMSError) {\n\tret1Item := []*pbmsku.MapUint64Item{}\n\tfor uid, id := range ret1 {\n\t\tret1Item = append(ret1Item, &pbmsku.MapUint64Item{\n\t\t\tMKey: convert.UInt64(uid),\n\t\t\tMVal: convert.Int64(id),\n\t\t})\n\n\t}\n\tresp := &pbmsku.CountShopByMerchantIDsResponse{\n\t\tRet1: ret1Item,\n\t}\n\treturn resp, nil\n}",
		"toGetAllCategoryMapByCountryPbResp":                "func toGetAllCategoryMapByCountryPbResp(ret1 map[int64]*entity.CategoryTree) (*pbmsku.GetAllCategoryMapByCountryResponse, *wmserror.WMSError) {\n\tret1Item := []*pbmsku.MapCategoryTreeItem{}\n\tfor id, tree := range ret1 {\n\t\titem := &pbmsku.CategoryTreeItem{}\n\t\tif jsErr := copier.Copy(tree, &item); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t\tret1Item = append(ret1Item, &pbmsku.MapCategoryTreeItem{\n\t\t\tId:   convert.Int64(id),\n\t\t\tItem: item,\n\t\t})\n\t}\n\tresp := &pbmsku.GetAllCategoryMapByCountryResponse{\n\t\tRet1: ret1Item,\n\t}\n\treturn resp, nil\n}",
		"toGetAllSKU2CalculateMappingPbResp":                "func toGetAllSKU2CalculateMappingPbResp(ret1 map[string][]string, ret2 map[string]string) (*pbmsku.GetAllSKU2CalculateMappingResponse, *wmserror.WMSError) {\n\tret1Items := toMapStrsItem(ret1)\n\n\tresp := &pbmsku.GetAllSKU2CalculateMappingResponse{\n\t\tRet1: ret1Items,\n\t\tRet2: toMapItemByStrMap(ret2),\n\t}\n\treturn resp, nil\n}\n\nfunc toMapStrsItem(ret1 map[string][]string) []*pbmsku.MapStrsItem {\n\tret1Items := []*pbmsku.MapStrsItem{}\n\tfor k, vals := range ret1 {\n\t\tret1Items = append(ret1Items, &pbmsku.MapStrsItem{\n\t\t\tMKey:  convert.String(k),\n\t\t\tMVals: vals,\n\t\t})\n\t}\n\treturn ret1Items\n}",
		"toGetParentCategoryIDChildCategoryMapPbResp":       "func toGetParentCategoryIDChildCategoryMapPbResp(ret1 map[int64][]*entity.CategoryTree) (*pbmsku.GetParentCategoryIDChildCategoryMapResponse, *wmserror.WMSError) {\n\tret1Items := []*pbmsku.MapCategoryTreeItemList{}\n\tfor id, trees := range ret1 {\n\t\titems := []*pbmsku.CategoryTreeItem{}\n\t\tif jsErr := copier.Copy(trees, &items); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\t\n\t\tret1Items = append(ret1Items, &pbmsku.MapCategoryTreeItemList{\n\t\t\tId: convert.Int64(id),\n\t\t\tList: items,\n\t\t})\n\t}\n\tresp := &pbmsku.GetParentCategoryIDChildCategoryMapResponse{\n\t\tRet1: ret1Items,\n\t}\n\treturn resp, nil\n}",
		"toGetSKU2CalculateMappingPbResp":                   "func toGetSKU2CalculateMappingPbResp(ret1 map[string][]string, ret2 map[string]string) (*pbmsku.GetSKU2CalculateMappingResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.GetSKU2CalculateMappingResponse{\n\t\tRet1: toMapStrsItem(ret1),\n\t\tRet2: toMapItemByStrMap(ret2),\n\t}\n\treturn resp, nil\n}",
		"toGetSKUCalculateMappingAndSKUListPbResp":          "func toGetSKUCalculateMappingAndSKUListPbResp(ret1 map[string][]string, ret2 map[string]string, ret3 []string) (*pbmsku.GetSKUCalculateMappingAndSKUListResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.GetSKUCalculateMappingAndSKUListResponse{\n\t\tRet1: toMapStrsItem(ret1),\n\t\tRet2: toMapItemByStrMap(ret2),\n\t\tRet3: ret3,\n\t}\n\treturn resp, nil\n}",
		"toGetSKUCalculateMappingAndSKUListWithSlicePbResp": "func toGetSKUCalculateMappingAndSKUListWithSlicePbResp(ret1 map[string][]string, ret2 map[string]string, ret3 []string) (*pbmsku.GetSKUCalculateMappingAndSKUListWithSliceResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.GetSKUCalculateMappingAndSKUListWithSliceResponse{\n\t\tRet1: toMapStrsItem(ret1),\n\t\tRet2: toMapItemByStrMap(ret2),\n\t\tRet3: ret3,\n\t}\n\treturn resp, nil\n}",
		"toGetSKUTagBySkuIDPbResp":                          "func toGetSKUTagBySkuIDPbResp(ret1 map[string][]*entity.SKUTagEntity) (*pbmsku.GetSKUTagBySkuIDResponse, *wmserror.WMSError) {\n\tret1Items, err:= toMapSkuTagsItems(ret1)\n\tif err != nil {\n\t\treturn nil, err.Mark()\n\t}\n\tresp := &pbmsku.GetSKUTagBySkuIDResponse{\n\t\tRet1: ret1Items,\n\t}\n\treturn resp, nil\n}\n",
		"toGetSKUTagBySkuWhsAttrPbResp":                     "func toMapSkuTagsItems(ret1 map[string][]*entity.SKUTagEntity) ([]*pbmsku.MapSKUTagsItem, *wmserror.WMSError) {\n\tret1Items := []*pbmsku.MapSKUTagsItem{}\n\tfor k, tagEntities := range ret1 {\n\t\titems := []*pbmsku.SKUTagEntityItem{}\n\t\tif jsErr := copier.Copy(tagEntities, &items); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t\tret1Items = append(ret1Items, &pbmsku.MapSKUTagsItem{\n\t\t\tSkuId: convert.String(k),\n\t\t\tTags:  items,\n\t\t})\n\t}\n\treturn ret1Items, nil\n}\nfunc toGetSKUTagBySkuWhsAttrPbResp(ret1 map[string][]*entity.SKUTagEntity) (*pbmsku.GetSKUTagBySkuWhsAttrResponse, *wmserror.WMSError) {\n\tret1Items, err:= toMapSkuTagsItems(ret1)\n\tif err != nil {\n\t\treturn nil, err.Mark()\n\t}\n\tresp := &pbmsku.GetSKUTagBySkuWhsAttrResponse{\n\t\tRet1: ret1Items,\n\t}\n\treturn resp, nil\n}",
		"toGetSkuIDListMbnMapPbResp":                        "func toGetSkuIDListMbnMapPbResp(ret1 map[string][]string) (*pbmsku.GetSkuIDListMbnMapResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.GetSkuIDListMbnMapResponse{\n\t\tRet1: toMapStrsItem(ret1),\n\t}\n\treturn resp, nil\n}",
		"toGetSkuIsBulKyMapByWhsIdAndSkuIdListPbResp":       "func toGetSkuIsBulKyMapByWhsIdAndSkuIdListPbResp(ret1 map[string]bool) (*pbmsku.GetSkuIsBulKyMapByWhsIdAndSkuIdListResponse, *wmserror.WMSError) {\n\tret1Item := toMapItemByBool(ret1)\n\tresp := &pbmsku.GetSkuIsBulKyMapByWhsIdAndSkuIdListResponse{\n\t\tRet1: ret1Item,\n\t}\n\treturn resp, nil\n}\n\nfunc toMapItemByBool(ret1 map[string]bool) []*pbmsku.MapItem {\n\tret1Item := []*pbmsku.MapItem{}\n\tfor k, v := range ret1 {\n\t\tret1Item = append(ret1Item, &pbmsku.MapItem{\n\t\t\tMKey:   convert.String(k),\n\t\t\tMValue: convert.String(expression.If(v, \"1\", \"0\").(string)),\n\t\t\tMType:  convert.String(\"bool\"),\n\t\t})\n\t}\n\treturn ret1Item\n}",
		"toGetSkuIsBulKyMapByWhsIdAndSkuItemListPbResp":     "func toGetSkuIsBulKyMapByWhsIdAndSkuItemListPbResp(ret1 map[string]bool) (*pbmsku.GetSkuIsBulKyMapByWhsIdAndSkuItemListResponse, *wmserror.WMSError) {\n\tret1Item := toMapItemByBool(ret1)\n\tresp := &pbmsku.GetSkuIsBulKyMapByWhsIdAndSkuItemListResponse{\n\t\tRet1: ret1Item,\n\t}\n\treturn resp, nil\n}",
		"toGetSkuIsBulKyTypeByWhsIdAndSkuIdPbResp":          "func toGetSkuIsBulKyTypeByWhsIdAndSkuIdPbResp(ret1 constant.SkuSizeType) (*pbmsku.GetSkuIsBulKyTypeByWhsIdAndSkuIdResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.GetSkuIsBulKyTypeByWhsIdAndSkuIdResponse{\n\t\tRet1: convert.Int64(ret1.ToInt64()),\n\t}\n\treturn resp, nil\n}",
		"toGetSkuIsBulKyTypeMapByWhsIdAndSkuIdListPbResp":   "func toMapItemBySkuSizeType(ret1 map[string]constant.SkuSizeType) []*pbmsku.MapItem {\n\tret1Item := []*pbmsku.MapItem{}\n\tfor k, v := range ret1 {\n\t\tret1Item = append(ret1Item, &pbmsku.MapItem{\n\t\t\tMKey:   convert.String(k),\n\t\t\tMValue: convert.String(convert.ToString(v)),\n\t\t\tMType:  convert.String(\"bool\"),\n\t\t})\n\t}\n\treturn ret1Item\n}\nfunc toGetSkuIsBulKyTypeMapByWhsIdAndSkuIdListPbResp(ret1 map[string]constant.SkuSizeType) (*pbmsku.GetSkuIsBulKyTypeMapByWhsIdAndSkuIdListResponse, *wmserror.WMSError) {\n\tret1Item := toMapItemBySkuSizeType(ret1)\n\n\tresp := &pbmsku.GetSkuIsBulKyTypeMapByWhsIdAndSkuIdListResponse{\n\t\tRet1: ret1Item,\n\t}\n\treturn resp, nil\n}",
		"toGetSkuIsHeavyMapByWhsIdAndSkuIdListPbResp":       "func toGetSkuIsHeavyMapByWhsIdAndSkuIdListPbResp(ret1 map[string]bool) (*pbmsku.GetSkuIsHeavyMapByWhsIdAndSkuIdListResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.GetSkuIsHeavyMapByWhsIdAndSkuIdListResponse{\n\t\tRet1: toMapItemByBool(ret1),\n\t}\n\treturn resp, nil\n}",
		"toGetSkuMtSKUMapPbResp":                            "func toGetSkuMtSKUMapPbResp(ret1 map[string]string) (*pbmsku.GetSkuMtSKUMapResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.GetSkuMtSKUMapResponse{\n\t\tRet1: toMapItemByStrMap(ret1),\n\t}\n\treturn resp, nil\n}",
		"toGetSkuScbsCannotUpdateFieldsTypeMapPbResp":       "func toMapIntsItem(ret1 map[string][]int64) []*pbmsku.MapIntsItem {\n\tret1Items := []*pbmsku.MapIntsItem{}\n\tfor k, vals := range ret1 {\n\t\tret1Items = append(ret1Items, &pbmsku.MapIntsItem{\n\t\t\tMKey:  convert.String(k),\n\t\t\tMVals: vals,\n\t\t})\n\t}\n\treturn ret1Items\n}\nfunc toGetSkuScbsCannotUpdateFieldsTypeMapPbResp(ret1 map[string][]int64) (*pbmsku.GetSkuScbsCannotUpdateFieldsTypeMapResponse, *wmserror.WMSError) {\n\tret1Items := []*pbmsku.MapIntsItem{}\n\tif jsErr := copier.Copy(ret1, &ret1Items); jsErr != nil {\n\t\treturn nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t}\n\tresp := &pbmsku.GetSkuScbsCannotUpdateFieldsTypeMapResponse{\n\t\tRet1: toMapIntsItem(ret1),\n\t}\n\treturn resp, nil\n}",
		"toGetSkuSetForHighValueByWhsIDPbResp":              "func toGetSkuSetForHighValueByWhsIDPbResp(ret1 *collection.StringSet) (*pbmsku.GetSkuSetForHighValueByWhsIDResponse, *wmserror.WMSError) {\n\tret1Item := []string{}\n\tif ret1 != nil {\n\t\tret1Item = ret1.ToSlice()\n\t}\n\tresp := &pbmsku.GetSkuSetForHighValueByWhsIDResponse{\n\t\tRet1: ret1Item,\n\t}\n\treturn resp, nil\n}",
		"toGetSupplierNameMappingBySupplierIDListMngPbResp": "func toGetSupplierNameMappingBySupplierIDListMngPbResp(ret1 map[msku.SupplierIDType]msku.SupplierNameType) (*pbmsku.GetSupplierNameMappingBySupplierIDListMngResponse, *wmserror.WMSError) {\n\tret1Item := []*pbmsku.MapItem{}\n\tfor k, v := range ret1 {\n\t\tret1Item = append(ret1Item, &pbmsku.MapItem{\n\t\t\tMKey:   convert.String(k),\n\t\t\tMValue: convert.String(v),\n\t\t\tMType: convert.String(\"string\"),\n\t\t})\n\t}\n\tresp := &pbmsku.GetSupplierNameMappingBySupplierIDListMngResponse{\n\t\tRet1: ret1Item,\n\t}\n\treturn resp, nil\n}",
		"toGetSKUCalculateMappingPbResp":                    "func toGetSKUCalculateMappingPbResp(ret1 map[string][]string) (*pbmsku.GetSKUCalculateMappingResponse, *wmserror.WMSError) {\n\tresp := &pbmsku.GetSKUCalculateMappingResponse{\n\t\tRet1: toMapStrsItem(ret1),\n\t}\n\treturn resp, nil\n}",
		"toGetSKUsDateFormatMapPbResp":                      "func toGetSKUsDateFormatMapPbResp(ret1 map[string]*entity.SkuProdExpiryDateFormatTab) (*pbmsku.GetSKUsDateFormatMapResponse, *wmserror.WMSError) {\n\tret1Item := []*pbmsku.MapSkuProdExpiryDateFormatTabItem{}\n\n\tfor skuID, dbItem := range ret1 {\n\t\titem:=&pbmsku.SkuProdExpiryDateFormatTabItem{}\n\t\tif jsErr := copier.Copy(dbItem, &item); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}\n\t\tret1Item = append(ret1Item, &pbmsku.MapSkuProdExpiryDateFormatTabItem{\n\t\t\tSkuId: convert.String(skuID),\n\t\t\tItem:  item,\n\t\t})\n\t}\n\t\n\tresp := &pbmsku.GetSKUsDateFormatMapResponse{\n\t\tRet1: ret1Item,\n\t}\n\treturn resp, nil\n}",
	},
}

var tplCodeMap = map[string]map[string]string{
	"msku": {
		"BuildCategoryTreeNodesByCategoryMapRequest":  "message BuildCategoryTreeNodesByCategoryMapRequest{\n  optional CategoryTreeItem category_item = 1;\n  repeated MapCategoryTreeItemList parent_category_child_map = 2;\n}",
		"UpdateSuggestZoneAndPathwayCoreRequest":      "message UpdateSuggestZoneAndPathwayCoreRequest{\n  optional string whs_id = 1;\n  repeated int64 delete_zone_pathways_category_ids = 2;\n  repeated CategoryZonePathwayConfTabItem create_zone_pathways = 3;\n  repeated MapCategoryZonePathwayConfList whs_category_id_zone_pathways_map = 4;\n  optional string operator = 5;\n}",
		"GetAllCategoryMapByCountryResponse":          "message GetAllCategoryMapByCountryResponse{\nrepeated MapCategoryTreeItem ret1 = 1;\n}",
		"GetSKUsDateFormatMapResponse":                "message GetSKUsDateFormatMapResponse{\nrepeated MapSkuProdExpiryDateFormatTabItem ret1 = 1;\n}",
		"GetParentCategoryIDChildCategoryMapResponse": "message GetParentCategoryIDChildCategoryMapResponse{\nrepeated MapCategoryTreeItemList ret1 = 1;\n}",
	},
}
var srcProxyCodeMap = map[string]map[string]string{
	"msku": {
		"GetExportShopListMng": "func (m *SKUManagerProxy) GetExportShopListMng(ctx context.Context, params *pbshop.ExportShopRequest, whsID string) ([]*entity.Shop, *wmserror.WMSError) {\n\tvar ret1 = []*entity.Shop{}\n\tvar err *wmserror.WMSError\n\toriginHandler := func(ctx context.Context) {\n\t\tret1, err = m.sKUManager.GetExportShopListMng(ctx, params, whsID)\n\t}\n\tproxyHandler := func(ctx context.Context) *wmserror.WMSError {\n\t\tvar item wmsbasic.ExportShopRequestItem\n\t\tif params != nil {\n\t\t\tif jsErr:=copier.Copy(params,&item);jsErr!=nil{\n\t\t\t\treturn wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t\t}\n\t\t}\n\t\tproxyRet1, proxyErr := m.sKUManagerProxyAPI.GetExportShopListMng(ctx, item, whsID)\n\t\terr = proxyErr\n\t\tif proxyErr != nil {\n\t\t\treturn proxyErr.Mark()\n\t\t}\n\t\tret1 = proxyRet1\n\t\treturn nil\n\t}\n\tendPoint := \"GetExportShopListMng\"\n\tgetBasicHandler()(ctx, endPoint, originHandler, proxyHandler)\n\treturn ret1, err\n}",
	},
}

type SyncSKUToESMessage struct {
	Region string
	SKUIDs []string
}

func TestName2222(t *testing.T) {
	println(ToPrettyJSON(&SyncSKUToESMessage{
		Region: "11",
		SKUIDs: []string{"11"},
	}))
}
