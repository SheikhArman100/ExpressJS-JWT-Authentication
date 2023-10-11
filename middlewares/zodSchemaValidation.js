const schemaValidation=(schema)=>(req,res,next)=>{
    try {
        schema.parse({
            body:req.body,
            query:req.query,
            params:req.params,

        })
        next()
    } catch (error) {
        console.log(`${error.message}  happens in ${schema}`)
        return res.status(400).send({message:error.message})
        
    }

}
module.exports={schemaValidation}