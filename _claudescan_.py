import langchain_community.vectorstores as vectorstores
import langchain_community.document_loaders as loaders
import langchain.chains.conversational_retrieval.base as chains
import langchain_anthropic as anthropic
import langchain_community.embeddings.huggingface as hf_embeddings
import os
import asyncio
import sys

class ServiceAnalyzer:
    def __init__(self):
        self.name = "Claude Service Analysis"
        self.PERSIST = True
        self.api_key = "KEY HERE"
        self.chain = self._setup_chain()

    def _setup_chain(self):
        # Initialize local embeddings model
        model_name = "all-MiniLM-L6-v2"
        embedding_func = hf_embeddings.HuggingFaceEmbeddings(
            model_name=model_name,
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': True}
        )

        # Setup the knowledge base
        if self.PERSIST and os.path.exists("persist"):
            #print("Reusing existing knowledge base...")
            vectorstore = vectorstores.Chroma(
                persist_directory="persist", 
                embedding_function=embedding_func
            )
        else:
            data_dir = os.path.join(os.path.dirname(__file__), 'training_data')
            loader = loaders.DirectoryLoader(data_dir)
            documents = loader.load()
            
            vectorstore = vectorstores.Chroma.from_documents(
                documents=documents,
                embedding=embedding_func,
                persist_directory="persist" if self.PERSIST else None
            )
            
            if self.PERSIST:
                vectorstore.persist()

        return chains.ConversationalRetrievalChain.from_llm(
            llm=anthropic.ChatAnthropic(
                model="claude-3-5-sonnet-20241022",
                anthropic_api_key=self.api_key,
                temperature=0.7
            ),
            retriever=vectorstore.as_retriever(search_kwargs={"k": 1}),
        )

    async def analyze_service(self, port, service, ip):
        query = f"""
        Give me commands to leverage against:
        Port: {port}
        Protocol: {service}
        IP: {ip}

        Provide only the commands and nothing else, format your response similar to the sample commands below:
        1. nmap -sV <ip>
        2. smbmap -H <ip> -P <port>

        """

        try:
            def invoke_chain():
                response = self.chain.invoke({
                    "question": query,
                    "chat_history": []
                })
                return response

            result = await asyncio.to_thread(invoke_chain)
            
            return result

                
        except Exception as e:
            print(f"Error in analyze_service: {str(e)}")
            return f"Error analyzing service: {str(e)}"

    async def analyze_target(self, port, service, ip):
        try:
            print(f"\nAnalyzing port {port}...")
            analysis = await self.analyze_service(port, service, ip)
            
            # Save analysis
            return analysis

        except Exception as e:
            print(f"Error analyzing target: {str(e)}")

async def main():
    if len(sys.argv) < 3:
        print("Usage: python script.py <port> <service> <ip>")
        sys.exit(1)
    
    analyzer = ServiceAnalyzer()
    results = await analyzer.analyze_target(sys.argv[1], sys.argv[2], sys.argv[3])
    # Parse the results and extract just the answer
    if isinstance(results, dict) and 'answer' in results:
        formatted_answer = results['answer']
        # Print with proper formatting
        print(formatted_answer)
    else:
        print(results)  # Fallback if results is not in expected format


if __name__ == "__main__":
    asyncio.run(main())
